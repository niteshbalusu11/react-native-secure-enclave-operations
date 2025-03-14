{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    android-nixpkgs = {
      url = "github:tadfisher/android-nixpkgs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      android-nixpkgs,
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            android_sdk.accept_license = true;
            platform = if system == "aarch64-darwin" then "aarch64-darwin" else "x86_64-darwin";
          };
        };

      androidSdkFor =
        system:
        android-nixpkgs.sdk.${system} (
          sdkPkgs: with sdkPkgs; [
            build-tools-34-0-0
            build-tools-35-0-0
            cmdline-tools-latest
            platform-tools
            platforms-android-34
            platforms-android-35
            ndk-27-1-12297006
            ndk-27-0-12077973
            cmake-3-22-1
          ]
        );

      # macOS-specific derivations
      darwinDerivations = {
        xcode-wrapper =
          pkgs:
          pkgs.stdenv.mkDerivation {
            name = "xcode-wrapper-16.2.0";
            buildInputs = [ pkgs.darwin.cctools ];
            buildCommand = ''
              mkdir -p $out/bin

              # Create wrapper scripts instead of symlinks
              cat > $out/bin/xcodebuild << EOF
              #!/bin/sh
              exec /usr/bin/xcodebuild "\$@"
              EOF

              cat > $out/bin/xcrun << EOF
              #!/bin/sh
              exec /usr/bin/xcrun "\$@"
              EOF

              cat > $out/bin/xcode-select << EOF
              #!/bin/sh
              exec /usr/bin/xcode-select "\$@"
              EOF

              cat > $out/bin/codesign << EOF
              #!/bin/sh
              exec /usr/bin/codesign "\$@"
              EOF

              cat > $out/bin/ld << EOF
              #!/bin/sh
              exec /usr/bin/ld "\$@"
              EOF

              cat > $out/bin/clang << EOF
              #!/bin/sh
              exec /usr/bin/clang "\$@"
              EOF

              # Make all wrapper scripts executable
              chmod +x $out/bin/*

              # Check if Xcode exists without using the wrappers
              if [ -d "/Applications/Xcode-16.2.0.app" ]; then
                DEVELOPER_DIR="/Applications/Xcode-16.2.0.app/Contents/Developer"
              elif [ -d "/Applications/Xcode.app" ]; then
                DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
              else
                echo "Error: Xcode not found"
                exit 1
              fi

              # Export the developer directory for the shell session
              echo "export DEVELOPER_DIR=\"$DEVELOPER_DIR\"" > $out/bin/env.sh
            '';
          };

        setupScript =
          pkgs:
          pkgs.writeScriptBin "setup-ios-env" ''
            #!${pkgs.stdenv.shell}
            export XCODE_VERSION="16.2.0"
            export XCODES_VERSION="1.6.0"

            if [ "$(uname)" = "Darwin" ]; then
              if [ -d "/Applications/Xcode.app" ]; then
                XCODE_PATH="/Applications/Xcode.app"
              elif [ -d "/Applications/Xcode-$XCODE_VERSION.app" ]; then
                XCODE_PATH="/Applications/Xcode-$XCODE_VERSION.app"
              else
                echo "Installing Xcode $XCODE_VERSION..."
                curl -L -o xcodes.zip "https://github.com/XcodesOrg/xcodes/releases/download/$XCODES_VERSION/xcodes.zip"
                unzip xcodes.zip
                ./xcodes install $XCODE_VERSION
                rm -f xcodes xcodes.zip
                XCODE_PATH="/Applications/Xcode-$XCODE_VERSION.app"
              fi

              echo "Switching to Xcode at $XCODE_PATH..."
              sudo xcode-select --switch "$XCODE_PATH/Contents/Developer"

              SELECTED_PATH=$(xcode-select -p)
              echo "Selected Xcode path: $SELECTED_PATH"

              echo "Accepting Xcode license..."
              sudo xcodebuild -license accept

              echo "Installing iOS simulator runtime..."
              xcrun simctl runtime add "iOS 17.0" || true

              echo "Xcode setup completed!"
              xcodebuild -version
            else
              echo "This script only works on macOS"
              exit 1
            fi
          '';
      };

      # System-specific shell configuration
      mkShellFor =
        system:
        let
          pkgs = pkgsFor system;
          androidSdk = androidSdkFor system;

          # Base packages for all systems
          basePackages = with pkgs; [
            nodejs_22
            yarn
            androidSdk
            jdk17
            bun
          ];

          # macOS-specific packages
          darwinPackages = with pkgs; [
            cocoapods
            ruby
            bundler
            darwin.apple_sdk.frameworks.CoreServices
            darwin.apple_sdk.frameworks.CoreFoundation
            darwin.apple_sdk.frameworks.Foundation
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.SystemConfiguration

            # pkg-config
            # openssl
            # libiconv
            # darwin.apple_sdk.frameworks.AppKit
            # darwin.apple_sdk.frameworks.WebKit
            # darwin.apple_sdk.frameworks.Carbon
            (darwinDerivations.xcode-wrapper pkgs)
            (darwinDerivations.setupScript pkgs)
          ];

          # Shell hook for macOS
          darwinHook = ''
            export LC_ALL=en_US.UTF-8
            export LANG=en_US.UTF-8

            # Source the Xcode environment file
            if [ -f "${darwinDerivations.xcode-wrapper pkgs}/bin/env.sh" ]; then
              source "${darwinDerivations.xcode-wrapper pkgs}/bin/env.sh"
            fi

            export PLATFORM_NAME=iphoneos
            export SDKROOT="$DEVELOPER_DIR/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk"
            export LD=/usr/bin/clang
            export LD_FOR_TARGET=/usr/bin/clang
            export IOS_DEPLOYMENT_TARGET=16.6

            sudo xcode-select --switch "$DEVELOPER_DIR"

            pod-install() {
              cd ios
              rm -rf Pods
              rm -rf ~/Library/Caches/CocoaPods
              pod cache clean --all

              DEVELOPER_DIR="$DEVELOPER_DIR" \
              SDKROOT="$SDKROOT" \
              LD="$LD" \
              LD_FOR_TARGET="$LD_FOR_TARGET" \
              pod install --repo-update
            }

            run-ios() {
              DEVELOPER_DIR="$DEVELOPER_DIR" \
              SDKROOT="$SDKROOT" \
              yarn react-native run-ios
            }

            echo "iOS development environment:"
            echo "DEVELOPER_DIR: $DEVELOPER_DIR"
            echo "SDKROOT: $SDKROOT"
            xcodebuild -version
            echo ""
            echo "Available commands:"
            echo "  pod-install  - Install CocoaPods dependencies"
            echo "  run-ios      - Run the app in iOS simulator"
          '';

          # Linux-specific shell hook
          linuxHook = ''
            export LC_ALL=en_US.UTF-8
            export LANG=en_US.UTF-8
          '';

        in
        pkgs.mkShellNoCC {
          buildInputs = if system == "aarch64-darwin" then basePackages ++ darwinPackages else basePackages;

          shellHook = if system == "aarch64-darwin" then darwinHook else linuxHook;
        };
    in
    {
      devShells = forAllSystems (system: {
        default = mkShellFor system;
      });
    };
}
