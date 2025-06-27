### Wallet Showcase Repository

This repo demonstrates a threshold‑based wallet built with Rust and WebAssembly:

Core (core/): FROST threshold key generation, AWS KMS envelope encryption, share serialization, Solana address derivation.

Server (server/): Actix‑web backend exposing REST endpoints for wallet creation and signing. Stores server shares in Postgres, encrypted via AWS KMS.

WASM SDK (wasm/): Browser‑compatible SDK (via wasm-bindgen) to call the server and manage client shares.

## Enjoy exploring threshold‐based wallets with Rust, AWS KMS, and WebAssembly!

### Prerequisites
# 1. Rust (latest stable)
    ->  Checked in 1.87.0

# 2. wasm32-unknown-unknown target:  rustup target add wasm32-unknown-unknown

# 3. Postgres database
    -> From root run: docker-compose up -d)

# 4. AWS credentials with KMS permissions
    -> From AWS console create a custom key to sign the keys

# 5. wasm-pack (or prebuilt wasm-bindgen in PATH)
    -> Note: cargo version of wasm-bindgen has issues, I downloaded directly and added it to my PATH

### Running the Server (Backend)

# 1. Configure environment:
    export DATABASE_URL=postgres://USER:PASS@localhost:5432/uniwallet
    export KMS_KEY_ID=alias/your-cmk
    export SERVER=127.0.0.1
    export PORT=8080

# 2. Apply migrations:
    cd server
    sqlx migrate run

# 3. Start the server:
    cargo run --release      # in `server/` folder

# 4. API is available at http://$SERVER:$PORT (e.g. http://127.0.0.1:8080/wallet/create).

### Building & Running the WASM SDK
# 1. Enter the WASM folder:
    cd wasm

# 2. Build the WebAssembly module:
    # Ensure wasm-pack sees wasm-bindgen CLI in $PATH
    wasm-pack build --target web

# 3. Include the generated pkg/ in your frontend app:
    <script type="module">
        import init, { register_wallet } from './pkg/wasm_sdk.js';
        await init();
        // call register_wallet("http://localhost:8080", params)
    </script>

# 4. See wasm/js/index.html for frontend sample code

### Run JS client
# 1. Enter the WASM folder:
    cd wasm

# 2. Serve JS over a NodeJS server
    npx serve # NodeJS required
    # Note which port - usually 3000

# 3. Open the JS client
    for localhost:
    http://localhost:3000/js

# 4. Click on Create Wallet button