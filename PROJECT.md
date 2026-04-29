# System Instructions: Verifiable Credentials (SD-JWT) Library

## Project Overview
This repository houses the **VerifiableCredentials** project, containing a production-grade library for Selective Disclosure for JWTs (SD-JWT) strictly adhering to RFC 9901. The library focuses on identity, verifiable credentials, and cryptographic token manipulation. The core capability enables developers to Parse, Issue, Present, and Verify SD-JWTs—including complex structured configurations, recursive nested data disclosures, Decoy padding natively inside arrays/objects, and Key Binding JWTs.

## Tech Stack
- **Language**: Kotlin 2.0+ (Idiomatic, Pure JVM Library)
- **Architecture**: Headless SDK, fully decoupled from Android, perfectly flattened at the root directory.
- **Build System**: Gradle (Kotlin DSL - `build.gradle.kts`) with **Gradle Version Catalogs** (`gradle/libs.versions.toml`).
- **Core Dependencies**:
  - `nimbus-jose-jwt` for base JWT processing, signing, and signature verification.
  - `bouncycastle` for advanced cryptographic primitives.
  - `kotlinx-serialization-json` for JSON serialization/deserialization tree mapping.
- **Testing**: `kotlin.test`
- **Publishing & CI/CD**: `maven-publish` and `signing` plugins configured for local/remote deployment, automated via GitHub Actions (`.github/workflows/ci.yml`).

## Coding Standards
- **Naming Conventions**: 
  - `PascalCase` for classes, sealed classes, and interfaces. `camelCase` for properties, parameters, and functions.
  - Test method names are wrapped in backticks with descriptive English phrases (e.g., `` `verify recursive and structured reconstruction` ``).
- **Architectural Patterns**: 
  - **Decoupled Architecture & SOLID Principles**: Strict separation of concerns between payload state and execution. Orchestration logic (e.g., `SdJwtIssuer`) must remain mathematically pure and stateless. Implementation-specific tools (e.g., `Sha256Hasher`, `SystemTimeProvider`) must be injected via interfaces to satisfy Dependency Inversion logic mapping specific operational components (e.g., `PayloadConcealer`).
  - **Idiomatic Kotlin DSLs**: Utilize idiomatic factory functions with trailing lambdas over rigid chains (e.g., `SdJwtClaims { ... }`) to elegantly define immutable boundaries, decoy digest configurations, and recursive claims constraints. Avoid polluting orchestrator classes with `.Builder()` instances.
  - **Type-Safe Domain Modeling (Zero "Stringly-Typed" Logic)**: Utilize strict bounding abstractions like the `ClaimPath` sealed class hierarchy (`Root`, `Claim`, `ArrayElement`) to natively dictate nested paths or structural coordinates safely across the pipeline, entirely preventing hidden string concatenation inaccuracies or unverified structural regressions.
  - **Immutability First**: Extensive use of Kotlin `data class` and `sealed class` (e.g., `SdJwt`, `Disclosure`) for immutable domain modeling.
- **Error Handling Architecture**: 
  - Exceptions (`IllegalArgumentException`, `IllegalStateException`) are strictly reserved for internal structural invariants and precondition evaluations (e.g., fast-failing via `require()`).
  - Public-facing library operations (`SdJwtParser.parse`, `SdJwtVerifier.verify`) exclusively wrap and return `Result<T>` to provide consuming applications with safe, functional unrolling logic.
- **SD-JWT Strict State Parsing & Security Constants**: 
  - Strictly enforce RFC 9901 Section 9.7 invariants using centralized constants map mappings (`SdJwtConstants.kt`); fundamentally block specific security-critical invariants (`iss`, `iat`, `sub`, `exp`, `vct`, `cnf`) from being mapped to structurally disclosable properties.
  - Recursive and Structured SD-JWT states must heavily differentiate between legitimate withheld nested disclosures (which are simply skipped/ignored during traversal) vs. unreferenced/garbage presentation disclosures (which MUST categorically fail the `SdJwtVerifier`).

## Project Shortcuts
To execute common tasks safely from the root directory:
- **Run Unit Tests**: `.\gradlew clean test`
- **Build Full Project**: `.\gradlew build`
- **Simulate Maven Publisher Locally**: `.\gradlew publishToMavenLocal`

## Development Rules
To maintain the integrity, security, and quality of the repository, all future contributions must adhere to these 5 Golden Rules:
1. **Strictly Enforce SRP & Interface Abstraction**: Core execution logic must never hardcode cryptographic implementations or payload configurations. Architect APIs utilizing DSL payloads parsed securely into independent execution classes via constructor parameter injection.
2. **Uphold Immutability & Type-Safety**: Domain mapping variables (e.g. tracking recursive JSON coordinates over arrays/objects) must utilize structured abstractions like `ClaimPath` rather than raw properties. Ensure state transitions evaluate boundaries immutably.
3. **Follow Specification Implicitly**: Any cryptographic or data-structure alterations MUST map back directly to IETF/W3C specifications (RFC 9901). Security-critical invariants evaluating decoy padding (`minimumDigests`) constraints and root claim disclosure enforcement must map seamlessly without state leakage.
4. **Maintain Defensive Parsing**: Never trust incoming JWT strings or JSON payloads. Precondition bounds checks (`require`) must immediately shield the internal classes prior to pipeline execution resolving structurally as `Result<T>`.
5. **No Logic Without Tests**: Every newly added constraint, parser adjustment, strictly framed path abstraction, DSL enhancement, or verifier branch requires a corresponding `kotlin.test` unit test mapped to a clear edge case or mathematical constraint verification.
