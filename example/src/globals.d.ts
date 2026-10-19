// Hermes provides `btoa` at runtime, but React Native's type definitions don't declare it.
declare function btoa(data: string): string;
