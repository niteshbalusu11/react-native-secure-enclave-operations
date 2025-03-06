# react-native-secure-enclave-operations

Perform cryptographic operations inside secure hardware for Android and iOS.

## Installation

```sh
npm install react-native-secure-enclave-operations react-native-nitro-modules

> `react-native-nitro-modules` is required as this library relies on [Nitro Modules](https://nitro.margelo.com/).
```

## Usage


```js
import { multiply } from 'react-native-secure-enclave-operations';

// ...

const result = multiply(3, 7);
```


## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
