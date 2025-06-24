# Account Generator

A simple Go tool to generate EVM or Solana private keys and save them to a JSON file.

## Usage

```bash
# Generate 10 EVM keys
go run cmd/keygen.go -type=evm -count=10

# Generate 10 Solana keys
go run cmd/keygen.go -type=solana -count=10

# Generate 10 Sui key
go run cmd/keygen.go -type=sui -count=10
```

## Parameters

- `-type`: Key type to generate (required)
  - Valid values: `evm` or `solana` or `sui`
- `-count`: Number of keypairs to generate (default: 1)

## Output

The output filename follows the pattern: `[type]_keys_[timestamp].json` 
