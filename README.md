# Policy-to-Outcome Compiler (POC)

Compiles human or institutional policy into machine-verifiable governance artifacts that ensure structural compliance and traceability.

## Overview

POC is a deterministic system that translates policy intent into executable constraints for three external governance systems: DIO (execution determinism), ZT-AAS (authority validation), and ICAE (cost attribution).

POC guarantees that policy is compiled into artifacts with provable backward auditability, where every execution, authorization, or cost artifact can be traced back to exactly one policy clause.

## Architecture

<pre>
+-------------------+
|   Policy Input    |
+-------------------+
          |
          v
+-------------------+
| Intent Normalizer |
+-------------------+
          |
          v
+--------------------+
|  Artifact Compiler |
|  - DIO Invariants  |
|  - ZT Authority    |
|  - ICAE Costs      |
+--------------------+
          |
          v
+--------------------+
|  Traceability Map  |
+--------------------+
          |
          v
+---------------------+
| Compilation Verdict |
+---------------------+
</pre>

## Components

### PolicyCompiler  
Main compilation engine that orchestrates the full pipeline from policy input through normalization, artifact generation, and traceability mapping.

### IntentNormalization  
Policy intent parsing and semantic validation. Detects modal language, multi-actions, and missing verbs. Rejects ambiguous input.

### DIOInvariant  
Execution constraints for deterministic behavior, compiled from policy clauses that govern how intelligence workflows must execute.

### ZTAuthority  
Authority scopes and delegation rules with explicit principals. All authority must be explicitly named (SYSTEM, USER, SERVICE); no inferred authority.

### ICAEConstraint  
Cost attribution and measurement constructs with explicit units. Cost clauses must include measurement units (USD, EUR, tokens, etc.).

### TraceabilityEntry  
Clause-to-artifact mapping ensuring exact traceability. Every compiled artifact maps back to exactly one policy clause.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test --test test_compiler
```

## Run

```bash
./poc # Linux/macOS

.\poc.exe # Windows
```

## Design Principles

1. **Determinism** - All outputs are deterministic from inputs with no implicit behavior.
2. **Explicitness** - No silent assumptions or inferred authority. Every principal must be explicitly named.
3. **Auditability** - Full traceability from execution to policy clause with exact mapping.
4. **Separation of Concerns** - Each artifact type is handled independently with strict boundaries.
5. **Fail Fast** - Semantic violations are detected and reported immediately without partial compilation.

## Requirements

- Rust 1.56+