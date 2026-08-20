# @slicekit/erc8128

## 0.4.1
### Patch Changes



- [`ce26fc0`](https://github.com/slice-so/monorepo/commit/ce26fc084603fc18de759762673d1c7b2dd219c3) Thanks [@jacopo-eth](https://github.com/jacopo-eth)! - First release of the ownership-refactor packages.
  
  - `@slicekit/abi`: new `@slicekit/abi/deployments` entry with chain ids,
    commerce and hook deployment facts, token addresses, wagmi contract configs,
    and hook-manifest lookups generated from canonical JSON inputs.
  - `@slicekit/commerce` (new): the shared commerce domain model — types, value
    sets, pricing math and formatting policy, currency/country rules, order
    status rules, metadata schemas, protocol constants, and the product category
    taxonomy (`@slicekit/commerce/categories`).
  - `@slicekit/wallet-primitives` (new, renamed from `@slicekit/wallet-protocol`):
    portable Slice Wallet protocol primitives — app permissions, root/permission
    authorization, factory validation, execution grants, chain manifests and
    policies — plus the Kernel v4 encoding under
    `@slicekit/wallet-primitives/kernel` (ABIs, deployment profiles, factory and
    proxy address derivation, install/nonce/permission encoding, install state,
    InstallPackages typed data). No ZeroDev dependencies.
  - `@slicekit/id-primitives` (new): Slice ID delegation parsing/verification and
    server-side primitives shared by the API and integrators.
  - `@slicekit/erc8128`: revocation registry constants consumed by the new
    packages.

## 0.4.0
### Minor Changes



- [#55](https://github.com/slice-so/monorepo/pull/55) [`d710fc9`](https://github.com/slice-so/monorepo/commit/d710fc90c907655eed78b04d039ad37a559ab3c1) Thanks [@jacopo-eth](https://github.com/jacopo-eth)! - Align delegated authentication with the final draft schema and deterministic
  CBOR vectors, including issuer-chain revocation batching, permission policy,
  single-use request requirements, and the clean-break local registry deployment.


- [#55](https://github.com/slice-so/monorepo/pull/55) [`60540a7`](https://github.com/slice-so/monorepo/commit/60540a71c1bb76493bce6c31697313fae2d89d95) Thanks [@jacopo-eth](https://github.com/jacopo-eth)! - Replace Slice ID certificates with chain-bound Registry authorizations and add
  presence-implies-coverage policy, exact signature-role tags, skew-safe nonce
  retention, atomic nonce-store adapters, and delegated-principal guidance.

### Patch Changes



- [#55](https://github.com/slice-so/monorepo/pull/55) [`803600b`](https://github.com/slice-so/monorepo/commit/803600b221897c501bed09f9eb565af72fe77e7b) Thanks [@jacopo-eth](https://github.com/jacopo-eth)! - Preserve an explicit signature expiry unless a discovered or authorization limit applies, enforce the strict default client floor for `Accept-Signature` retries, and treat an empty `classBoundPolicies` list as disabling class-bound signatures.
