# Verifiable Credentials SD-JWT

A production-grade Kotlin/JVM library for **Selective Disclosure JWTs (SD-JWT)** implementing
[RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html). Issue, parse, present, and verify
SD-JWTs with support for flat, structured, and recursive disclosures, decoy digest padding,
and Key Binding JWTs.

**Kotlin 2.3.21** | **JVM 11+** | **RFC 9901 Compliant**

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Architecture](#architecture)
- [Use Cases Supported](#use-cases-supported)
  - [Issuance](#issuance)
  - [Parsing](#parsing)
  - [Holder Presentation](#holder-presentation)
  - [Verification](#verification)
  - [Recreate Original Claims](#recreate-original-claims)
- [DSL Reference](#dsl-reference)
  - [Flat SD-JWT](#flat-sd-jwt)
  - [Structured SD-JWT](#structured-sd-jwt)
  - [Recursive SD-JWT](#recursive-sd-jwt)
  - [Array Disclosures](#array-disclosures)
- [Decoy Digests](#decoy-digests)
- [Key Binding JWT](#key-binding-jwt)
- [SD-JWT VC Support](#sd-jwt-vc-support)
- [How to Contribute](#how-to-contribute)
- [License](#license)

## Overview

This library provides a complete, type-safe implementation of the
[Selective Disclosure for JWTs (SD-JWT)](https://www.rfc-editor.org/rfc/rfc9901.html) specification
in **Kotlin**, targeting **JVM 11+**. It enables developers to:

- **Issue** SD-JWTs with fine-grained control over which claims are selectively disclosable
- **Parse** SD-JWT strings into structured domain models with resolved claim paths
- **Present** SD-JWTs by selectively disclosing a subset of claims to a verifier
- **Verify** SD-JWT presentations with strict unused-disclosure detection and optional Key Binding

The library leverages an idiomatic **Kotlin DSL** built on top of
[KotlinX Serialization](https://github.com/Kotlin/kotlinx.serialization) for defining JSON
payloads and disclosure configurations. Cryptographic operations are powered by
[Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) and
[BouncyCastle](https://www.bouncycastle.org/), with all implementations injected via
interfaces to satisfy Dependency Inversion.

### Key Features

| Feature | Description |
|---|---|
| **Kotlin 2.3 / JVM 11+** | Built with Kotlin 2.3 and targets JVM 11 |
| **RFC 9901 Compliant** | Full lifecycle support: issuance, presentation, verification |
| **Kotlin DSL** | Fluent, type-safe builder for claim concealment configuration |
| **Three Disclosure Modes** | Flat, Structured, and Recursive selective disclosure |
| **Decoy Padding** | Configurable minimum digest counts to prevent inference attacks |
| **Key Binding JWT** | RFC-compliant holder binding with `cnf` / `sd_hash` validation |
| **Type-Safe Paths** | `ClaimPath` sealed class hierarchy — zero string concatenation |
| **SOLID Architecture** | Stateless orchestrators, injected interfaces, immutable models |
| **Security Hardening** | Blocks disclosure of critical claims (`iss`, `exp`, `sub`, `cnf`, etc.) |

## Installation

The library is published as a Maven artifact. Add it to your project using your preferred
build tool:

### Gradle (Kotlin DSL)

```kotlin
// build.gradle.kts
dependencies {
    implementation("io.github.b2y4n:sdjwt-kt:1.0.0-alpha")
}
```

### Gradle (Groovy DSL)

```groovy
// build.gradle
dependencies {
    implementation 'io.github.b2y4n:sdjwt-kt:1.0.0-alpha'
}
```

### Maven

```xml
<dependency>
    <groupId>io.github.b2y4n</groupId>
    <artifactId>sdjwt-kt</artifactId>
    <version>1.0.0-alpha</version>
</dependency>
```

### Local Development

To build and publish locally for development:

```bash
./gradlew publishToMavenLocal
```

## Architecture

The library is organized into seven focused packages, each enforcing a single responsibility:

```
com.b2y4n.vc.sdjwt
├── crypto/          # Hasher interface + SHA-256 implementation
├── issuer/          # SdJwtIssuer, SdJwtClaims DSL, PayloadConcealer, SaltGenerator
├── models/          # SdJwt, Disclosure, ClaimPath, SdJwtPresentation, SdJwtConstants
├── parser/          # SdJwtParser — structural parsing with path resolution
├── presenter/       # SdJwtPresenter, KbJwtSigner — selective disclosure with Key Binding
├── utils/           # TimeProvider abstraction for deterministic testing
└── verifier/        # SdJwtVerifier, PayloadReconstructor, Signature & KB verification
```

All orchestration classes (`SdJwtIssuer`, `SdJwtVerifier`) are **stateless** and receive
their dependencies through constructor injection:

```
┌──────────────┐        ┌──────────────┐        ┌──────────────┐
│   Hasher     │◄───────│  SdJwtIssuer │───────►│  JwtSigner   │
│  (sha-256)   │        │  (stateless) │        │  (interface) │
└──────────────┘        └──────┬───────┘        └──────────────┘
                               │
                     ┌─────────▼─────────┐
                     │ PayloadConcealer  │
                     │ (recursive tree   │
                     │  transformation)  │
                     └───────────────────┘

┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ SdJwtPresenter  │◄───│  SdJwtVerifier   │───►│ SignatureVerifier│
│  (KbJwtSigner)  │    │   (stateless)    │    │   (interface)    │
└─────────────────┘    └────────┬─────────┘    └──────────────────┘
                                │
                      ┌─────────▼───────────┐    ┌──────────────────┐
                      │ PayloadReconstructor│    │KeyBindingVerifier│
                      │   (usedHashes set)  │    │   (interface)    │
                      └─────────────────────┘    └──────────────────┘
```

## Use Cases Supported

- [**Issuance**](#issuance): As an Issuer, use the library to produce an SD-JWT
- [**Parsing**](#parsing): Parse a raw SD-JWT string into a typed domain model
- [**Holder Presentation**](#holder-presentation): As a Holder, create a presentation disclosing selected claims
- [**Verification**](#verification): As a Verifier, validate an SD-JWT presentation
- [**Recreate Original Claims**](#recreate-original-claims): Reconstruct the clear-text payload from disclosures

---

### Issuance

To issue an SD-JWT, an Issuer must:

1. Define the claims payload and which claims to make selectively disclosable using the
   [DSL](#dsl-reference)
2. Provide a `JwtSigner` implementation wrapping their signing key
3. Provide a `SaltGenerator` that produces cryptographically random salts (≥128 bits of entropy)

```kotlin
import com.b2y4n.vc.sdjwt.issuer.*
import com.b2y4n.vc.sdjwt.models.ClaimPath

// 1. Define claims using the DSL
val claims = SdJwtClaims {
    claim("iss", "https://issuer.example")
    claim("iat", 1683000000)
    claim("exp", 1883000000)
    claim("sub", "user-1234")
    sdClaim("given_name", "John")
    sdClaim("family_name", "Doe")
    sdClaim("email", "john@example.com")
    objClaim("address") {
        sdClaim("street_address", "123 Main St")
        sdClaim("locality", "Anytown")
        sdClaim("region", "CA")
        sdClaim("country", "US")
    }
}

// 2. Provide a JwtSigner (e.g., wrapping Nimbus ES256)
val signer: JwtSigner = MyNimbusJwtSigner(ecKeyPair, "ES256")
val saltGenerator: SaltGenerator = MySecureRandomSaltGenerator()

// 3. Issue the SD-JWT
val issuer = SdJwtIssuer(signer, saltGenerator)
val sdJwtString: String = issuer.issue(claims)
// Output: <jwt>~<disclosure_1>~<disclosure_2>~...~<disclosure_n>~
```

The resulting SD-JWT string contains the signed base JWT followed by `~`-delimited
Base64url-encoded disclosures.

> [!TIP]
> The `SdJwtIssuer` automatically sets the JWS header `typ` to `sd-jwt` and appends
> the `_sd_alg` claim to the payload. You can override the header by passing a custom
> `JsonObject` to the `issue()` method.

> [!IMPORTANT]
> RFC 9901 Section 9.7 mandates that security-critical claims (`iss`, `exp`, `sub`, `iat`,
> `nbf`, `vct`, `cnf`) **cannot** be made selectively disclosable at the root level. The
> DSL enforces this at build time and will throw `IllegalArgumentException` if violated.

---

### Parsing

The `SdJwtParser` performs structural parsing **without** cryptographic verification,
adhering to Single Responsibility:

```kotlin
import com.b2y4n.vc.sdjwt.parser.SdJwtParser
import com.b2y4n.vc.sdjwt.models.SdJwt

val parser = SdJwtParser()

val result: Result<SdJwt> = parser.parse(sdJwtString)

result.onSuccess { sdJwt ->
    println("JWT: ${sdJwt.jwt}")
    println("Disclosures: ${sdJwt.disclosures.size}")
    println("Key Binding JWT: ${sdJwt.kbJwt}")

    // Each disclosure has a resolved ClaimPath
    sdJwt.disclosures.forEach { disclosure ->
        println("  ${disclosure.path} -> ${disclosure.claimName}: ${disclosure.claimValue}")
    }
}
```

> [!NOTE]
> The parser automatically resolves `ClaimPath` mappings by traversing the JWT payload and
> matching disclosure hashes against `_sd` arrays and `...` array decoy keys.

---

### Holder Presentation

A Holder creates a presentation by selecting which claims to disclose using type-safe
`ClaimPath` selectors:

```kotlin
import com.b2y4n.vc.sdjwt.presenter.SdJwtPresenter
import com.b2y4n.vc.sdjwt.models.ClaimPath

// Start from a parsed SdJwt (obtained via SdJwtParser)
val presenter = SdJwtPresenter(issuedSdJwt)

val presentation = presenter
    .select(ClaimPath.claim("given_name"))
    .select(ClaimPath.claim("address").claim("country"))
    .build()

// Serialize the presentation
val presentationString = presentation.toString()
// Output: <jwt>~<disclosure_given_name>~<disclosure_address>~<disclosure_country>~
```

Path relationships are honored automatically — selecting  `address.country` implicitly
includes the parent `address` disclosure if it was itself selectively disclosable
(`sdObjClaim`).

> [!TIP]
> For Key Binding support, chain `.kbSigner(...)`, `.aud(...)`, and `.nonce(...)` before
> calling `.build()`. See [Key Binding JWT](#key-binding-jwt) for details.

---

### Verification

The `SdJwtVerifier` performs end-to-end verification of SD-JWT presentations:

```kotlin
import com.b2y4n.vc.sdjwt.verifier.*
import com.b2y4n.vc.sdjwt.parser.SdJwtParser
import com.nimbusds.jose.crypto.ECDSAVerifier

// 1. Set up the verification pipeline
val parser = SdJwtParser()
val signatureVerifier = SignatureVerifierImpl(ECDSAVerifier(issuerPublicKey))

// 2. (Optional) Key Binding verifier
val kbVerifier = KeyBindingVerifierImpl(
    expectedAudience = "https://verifier.example",
    expectedNonce = "challenge-nonce-123",
    maxAgeSeconds = 300
)

val verifier = SdJwtVerifier(
    parser = parser,
    signatureVerifier = signatureVerifier,
    keyBindingVerifier = kbVerifier
)

// 3. Verify and reconstruct
val result: Result<JsonObject> = verifier.verify(presentationString)

result.onSuccess { claims ->
    println("Verified payload: $claims")
}.onFailure { error ->
    println("Verification failed: ${error.message}")
}
```

The verification pipeline:

1. **Parse** — Splits the SD-JWT into JWT, disclosures, and optional KB-JWT
2. **Signature** — Validates the base JWT signature via `SignatureVerifier`
3. **Key Binding** — Validates `aud`, `nonce`, `iat`, signature, and `sd_hash` (if KB-JWT present)
4. **Reconstruction** — Resolves all disclosure digests and reconstructs the clear-text payload

> [!CAUTION]
> The verifier **strictly fails** if any disclosure is unused after reconstruction.
> Unreferenced disclosures indicate a malformed or potentially malicious presentation
> and must cause verification failure per RFC 9901.

---

### Recreate Original Claims

Given a parsed `SdJwt` (either issuance or presentation), the original clear-text claims
can be reconstructed by resolving all disclosure digests:

```kotlin
import com.b2y4n.vc.sdjwt.verifier.PayloadReconstructor
import com.b2y4n.vc.sdjwt.crypto.Sha256Hasher

val hasher = Sha256Hasher()
val disclosureMap = sdJwt.disclosures.associateBy { hasher.hashBase64Url(it.encoded) }

val reconstructor = PayloadReconstructor(disclosureMap)
val originalClaims = reconstructor.reconstruct(basePayload)
```

The reconstructed output for a structured SD-JWT would look like:

```json
{
  "iss": "https://issuer.example",
  "iat": 1683000000,
  "exp": 1883000000,
  "sub": "user-1234",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "CA",
    "country": "US"
  }
}
```

## DSL Reference

The `SdJwtClaims { }` DSL provides a fluent, idiomatic Kotlin builder for defining
SD-JWT claim configurations. All examples assume the following target claim set:

```json
{
  "sub": "user-1234",
  "given_name": "John",
  "family_name": "Doe",
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "country": "US"
  }
}
```

### Flat SD-JWT

Every claim is individually disclosable. The JWT payload contains only `_sd` digest
arrays and the cleartext claims:

```kotlin
val claims = SdJwtClaims {
    claim("sub", "user-1234")                // Always visible
    sdClaim("given_name", "John")            // Selectively disclosable
    sdClaim("family_name", "Doe")            // Selectively disclosable
    sdClaim("email", "john@example.com")     // Selectively disclosable
}
```

**Result**: The JWT payload contains `sub` in cleartext, with `given_name`, `family_name`,
and `email` replaced by digest entries in the `_sd` array.

### Structured SD-JWT

An object claim is visible in the payload, but its **child properties** are individually
disclosable:

```kotlin
val claims = SdJwtClaims {
    claim("sub", "user-1234")
    objClaim("address") {                    // Object visible in payload
        sdClaim("street_address", "123 Main St")  // Child is disclosable
        sdClaim("locality", "Anytown")             // Child is disclosable
        claim("country", "US")                     // Child always visible
    }
}
```

**Result**: The `address` object is always present in the JWT, but its `street_address`
and `locality` children are replaced by digests inside `address._sd`.

### Recursive SD-JWT

The object itself is disclosable, **and** its children may also be individually disclosable.
This creates a multi-level disclosure tree:

```kotlin
val claims = SdJwtClaims {
    claim("sub", "user-1234")
    sdObjClaim("address") {                  // Entire object is disclosable
        sdClaim("street_address", "123 Main St")  // Nested child also disclosable
        sdClaim("locality", "Anytown")             // Nested child also disclosable
        claim("country", "US")                     // Always visible if address disclosed
    }
}
```

**Result**: The `address` key itself is a disclosure in the root `_sd` array. When
disclosed, its value is an object that itself contains an `_sd` array with the
`street_address` and `locality` digests.

### Array Disclosures

Arrays support element-level selective disclosure using `arrClaim` and `sdArrClaim`:

```kotlin
val claims = SdJwtClaims {
    claim("sub", "user-1234")
    arrClaim("nationalities") {              // Array visible in payload
        claim("US")                       // Element always visible
        sdClaim("DE")                     // Element selectively disclosable
    }
    sdArrClaim("phone_numbers") {            // Entire array is disclosable
        claim("+1-555-0100")
        sdClaim("+49-170-0000000")        // Nested element also disclosable
    }
}
```

### DSL Method Summary

| Object Builder | Description |
|---|---|
| `claim(key, value)` | Cleartext claim, always visible |
| `sdClaim(key, value)` | Selectively disclosable key-value pair |
| `objClaim(key) { }` | Cleartext nested object with disclosable children |
| `sdObjClaim(key) { }` | Disclosable nested object (recursive) |
| `arrClaim(key) { }` | Cleartext array with disclosable elements |
| `sdArrClaim(key) { }` | Disclosable array (recursive) |

| Array Builder | Description |
|---|---|
| `claim(value)` | Cleartext array element |
| `sdClaim(value)` | Selectively disclosable array element |
| `objClaim { }` | Cleartext nested object as array element |
| `sdObjClaim { }` | Disclosable nested object as array element |

## Decoy Digests

Decoy digests obscure the true number of concealed claims, preventing verifier inference
attacks. The library supports per-level `minimumDigests` configuration:

```kotlin
val claims = SdJwtClaims(minimumDigests = 5) {
    // Root _sd array will have at least 5 entries (real + decoy)
    sdClaim("given_name", "John")
    sdClaim("family_name", "Doe")
    // 2 real digests + 3 decoys = 5 minimum entries

    objClaim("address", minimumDigests = 8) {
        // Nested _sd array will have at least 8 entries
        sdClaim("street_address", "123 Main St")
        sdClaim("locality", "Anytown")
    }

    sdObjClaim("employment", minimumDigests = 4) {
        // This affects the _sd array inside the disclosed object
        sdClaim("employer", "ACME Corp")
    }

    arrClaim("nationalities", minimumDigests = 3) {
        // Array will have at least 3 {...} digest wrappers
        sdClaim("US")
    }
}
```

> [!TIP]
> Decoy digests are cryptographically random bytes of the correct hash length, making them
> indistinguishable from real disclosure digests. If the number of real digests already
> exceeds `minimumDigests`, no decoys are added.

## Key Binding JWT

Key Binding proves that the presenter possesses the private key corresponding to the
public key embedded in the `cnf` claim of the base JWT:

### Issuance with Holder Key

Include the holder's public key in the `cnf` claim during issuance:

```kotlin
val claims = SdJwtClaims {
    claim("iss", "https://issuer.example")
    claim("sub", "user-1234")
    claim("cnf", buildJsonObject {
        put("jwk", holderPublicKeyAsJsonObject)
    })
    sdClaim("given_name", "John")
}
```

### Presentation with Key Binding

```kotlin
val presentation = SdJwtPresenter(issuedSdJwt)
    .select(ClaimPath.claim("given_name"))
    .kbSigner(myKbJwtSigner)                // Signs the KB-JWT with holder's private key
    .aud("https://verifier.example")         // Verifier's audience URI
    .nonce("challenge-from-verifier")        // Verifier's replay protection nonce
    .build()

// Output: <jwt>~<disclosure>~<kb_jwt>
```

### Verification with Key Binding

```kotlin
val kbVerifier = KeyBindingVerifierImpl(
    expectedAudience = "https://verifier.example",
    expectedNonce = "challenge-from-verifier",
    maxAgeSeconds = 300  // 5-minute window (default)
)

val verifier = SdJwtVerifier(
    parser = SdJwtParser(),
    signatureVerifier = SignatureVerifierImpl(issuerJwsVerifier),
    keyBindingVerifier = kbVerifier
)

verifier.verify(presentationString).getOrThrow()
```

The `KeyBindingVerifierImpl` validates:
- Header `typ` is `kb+jwt`
- Signature matches the `cnf.jwk` from the base JWT
- `aud` matches the expected audience
- `nonce` matches the expected challenge
- `iat` is within the acceptable time window (with 60s clock skew tolerance)
- `sd_hash` matches the SHA-256 digest of the presentation string

## SD-JWT VC Support

The library supports [SD-JWT-based Verifiable Credentials](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-13.html)
by allowing the `vct` (Verifiable Credential Type) claim:

```kotlin
val vcClaims = SdJwtClaims {
    claim("iss", "https://issuer.example")
    claim("iat", 1683000000)
    claim("exp", 1883000000)
    claim("vct", "https://credentials.example/identity_credential")
    claim("cnf", buildJsonObject {
        put("jwk", holderPublicKeyAsJsonObject)
    })
    sdClaim("given_name", "John")
    sdClaim("family_name", "Doe")
    sdClaim("birthdate", "1990-01-01")
    sdObjClaim("address") {
        sdClaim("street_address", "123 Main St")
        sdClaim("locality", "Anytown")
        sdClaim("region", "CA")
        sdClaim("country", "US")
    }
}
```

> [!NOTE]
> The `vct` claim is treated as security-critical per RFC 9901 Section 9.7 and cannot be
> made selectively disclosable at the root level.

## How to Contribute

We welcome contributions from the community. To get started:

1. **Fork** the repository
2. **Create a feature branch** (`git checkout -b feature/my-improvement`)
3. **Make your changes** following the coding standards in [`PROJECT.md`](PROJECT.md)
4. **Add tests** — every new constraint, path abstraction, DSL enhancement, or verifier
   branch requires a corresponding `kotlin.test` unit test
5. **Run the test suite**:
   ```bash
   ./gradlew clean test
   ```
6. **Submit a Pull Request** with a clear description of your changes

### Development Rules

| Rule | Description |
|---|---|
| **SRP & Interface Abstraction** | Core logic must never hardcode cryptographic implementations |
| **Immutability & Type-Safety** | Use `ClaimPath` and `data class` — no raw string paths |
| **Specification Compliance** | All changes must map to RFC 9901 / IETF / W3C specifications |
| **Defensive Parsing** | Use `require()` guards and return `Result<T>` on public surfaces |
| **No Logic Without Tests** | Every new feature requires a corresponding unit test |

## License

This project is licensed under the **Apache License, Version 2.0**.

```
Copyright 2026 Bryan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
