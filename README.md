# Serum - Decentralized Electronic Health Records on ICP

Serum is a patient-owned, decentralized Electronic Health Record (EHR) system built on the Internet Computer Protocol (ICP). It leverages Internet Identity's verifiable credentials and privacy-preserving architecture to give patients full control over their medical data.

## 🌟 Features

### Decentralized Identity (DID)
- Each patient has a unique Decentralized Identifier (DID) derived from their Internet Identity
- DIDs follow the format: `did:icp:<principal_id>`
- Privacy-preserving authentication without passwords

### Encrypted Medical Records
- All medical records are encrypted using AES-256-GCM before storage
- Encryption keys are managed client-side, ensuring only patients can access their data
- Records are stored in patient-controlled canisters on the Internet Computer

### Selective Sharing
- Grant healthcare providers temporary access to specific records
- Fine-grained permission control (Read, Write, Delete)
- Time-limited access with automatic expiration
- Instant revocation capability

### Supported Record Types
- Diagnoses
- Prescriptions
- Lab Results
- Imaging Studies
- Procedures
- Vaccinations
- Allergies
- Vital Signs
- Other medical documents

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Serum EHR System                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌─────────────┐ │
│  │   Frontend   │────▶│   Backend    │────▶│  Internet   │ │
│  │   Canister   │     │   Canister   │     │  Identity   │ │
│  │  (Assets)    │◀────│  (Motoko)    │◀────│  Canister   │ │
│  └──────────────┘     └──────────────┘     └─────────────┘ │
│         │                    │                              │
│         │                    │                              │
│         ▼                    ▼                              │
│  ┌──────────────┐     ┌──────────────┐                     │
│  │ Client-Side  │     │   Stable     │                     │
│  │  Encryption  │     │   Storage    │                     │
│  │  (AES-256)   │     │              │                     │
│  └──────────────┘     └──────────────┘                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
serum-icp-ehr/
├── dfx.json                    # DFX configuration
├── package.json                # Node.js dependencies
├── README.md                   # This file
├── LICENSE                     # MIT License
├── src/
│   ├── serum_backend/
│   │   └── src/
│   │       └── main.mo         # Backend canister (Motoko)
│   └── serum_frontend/
│       ├── src/
│       │   ├── index.html      # Frontend HTML
│       │   └── index.js        # Frontend JavaScript
│       └── assets/
│           └── styles.css      # CSS styles
└── tests/
    └── serum_backend.test.mo   # Backend tests
```

## 🚀 Getting Started

### Prerequisites

1. **Install DFX SDK** (DFINITY Canister SDK):
   ```bash
   sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"
   ```

2. **Install Node.js** (v16 or later):
   ```bash
   # Using nvm
   nvm install 18
   nvm use 18
   ```

### Local Development

1. **Clone the repository**:
   ```bash
   git clone https://github.com/kunal-drall/serum-icp-ehr.git
   cd serum-icp-ehr
   ```

2. **Start the local Internet Computer replica**:
   ```bash
   dfx start --background
   ```

3. **Deploy Internet Identity locally** (for authentication):
   ```bash
   dfx deploy internet_identity
   ```

4. **Deploy the Serum canisters**:
   ```bash
   dfx deploy
   ```

5. **Access the application**:
   - Frontend: `http://localhost:4943?canisterId=<frontend_canister_id>`
   - Backend Candid UI: `http://localhost:4943?canisterId=<candid_ui_canister_id>&id=<backend_canister_id>`

### Production Deployment

1. **Configure for mainnet**:
   ```bash
   dfx deploy --network ic
   ```

2. **Access on mainnet**:
   - The frontend will be available at: `https://<frontend_canister_id>.ic0.app`

## 🔐 Security

### Encryption
- Medical data is encrypted client-side using **AES-256-GCM**
- Encryption keys are generated using the **Web Crypto API**
- Keys are stored locally and never transmitted to the canister

### Authentication
- Uses **Internet Identity** for passwordless, secure authentication
- Each session creates a delegated identity
- No passwords to leak or steal

### Access Control
- Only patients can access their own records by default
- Healthcare providers need explicit grants
- Grants can be time-limited and revoked instantly
- All access is logged and auditable

## 📚 API Reference

### DID Management

| Function | Description |
|----------|-------------|
| `createDID()` | Creates a unique DID for the authenticated user |
| `getMyDID()` | Retrieves the caller's DID |
| `resolveDID(identifier)` | Verifies if a DID exists |

### Patient Profile

| Function | Description |
|----------|-------------|
| `createOrUpdateProfile(name, dob, bloodType, allergies)` | Creates or updates patient profile |
| `getMyProfile()` | Retrieves the caller's profile |

### Medical Records

| Function | Description |
|----------|-------------|
| `addMedicalRecord(type, encryptedData, keyHash, metadata)` | Adds an encrypted medical record |
| `getMedicalRecord(id)` | Retrieves a specific record |
| `getMyMedicalRecords()` | Retrieves all records for the caller |
| `updateMedicalRecord(id, encryptedData, keyHash, metadata)` | Updates an existing record |
| `deleteMedicalRecord(id)` | Deletes a medical record |

### Access Control

| Function | Description |
|----------|-------------|
| `grantAccess(provider, recordIds, permissions, expiry)` | Grants access to a provider |
| `revokeAccess(provider)` | Revokes all access for a provider |
| `getMyAccessGrants()` | Lists all grants made by the caller |
| `getAccessibleRecords()` | Lists records accessible to the caller as a provider |

## 🧪 Testing

Run the backend tests:
```bash
dfx build serum_backend
dfx canister call serum_backend getTotalPatients
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [DFINITY Foundation](https://dfinity.org/) for the Internet Computer
- [Internet Identity](https://identity.ic0.app/) for decentralized authentication
- The ICP developer community

## 📞 Support

For questions and support, please open an issue in this repository