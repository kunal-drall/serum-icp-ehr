// Serum EHR - Frontend JavaScript
// Integration with Internet Identity and Backend Canister

import { AuthClient } from "@dfinity/auth-client";
import { Actor, HttpAgent } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";

// Constants
const NANOSECONDS_PER_MILLISECOND = 1000000;

// Canister IDs - will be set from environment or dfx
const BACKEND_CANISTER_ID = process.env.CANISTER_ID_SERUM_BACKEND || "bkyz2-fmaaa-aaaaa-qaaaq-cai";
const II_CANISTER_ID = process.env.CANISTER_ID_INTERNET_IDENTITY || "rdmx6-jaaaa-aaaaa-aaadq-cai";

// Backend canister interface
const idlFactory = ({ IDL }) => {
    const DID = IDL.Record({
        method: IDL.Text,
        identifier: IDL.Text,
        createdAt: IDL.Int,
    });

    const PatientProfile = IDL.Record({
        did: DID,
        name: IDL.Text,
        dateOfBirth: IDL.Text,
        bloodType: IDL.Opt(IDL.Text),
        allergies: IDL.Vec(IDL.Text),
        createdAt: IDL.Int,
        updatedAt: IDL.Int,
    });

    const RecordType = IDL.Variant({
        Diagnosis: IDL.Null,
        Prescription: IDL.Null,
        LabResult: IDL.Null,
        Imaging: IDL.Null,
        Procedure: IDL.Null,
        Vaccination: IDL.Null,
        Allergy: IDL.Null,
        VitalSigns: IDL.Null,
        Other: IDL.Null,
    });

    const RecordMetadata = IDL.Record({
        title: IDL.Text,
        provider: IDL.Text,
        facility: IDL.Opt(IDL.Text),
        dateOfService: IDL.Text,
        tags: IDL.Vec(IDL.Text),
    });

    const MedicalRecord = IDL.Record({
        id: IDL.Nat,
        patientDid: IDL.Text,
        recordType: RecordType,
        encryptedData: IDL.Vec(IDL.Nat8),
        encryptionKeyHash: IDL.Text,
        metadata: RecordMetadata,
        createdAt: IDL.Int,
        updatedAt: IDL.Int,
    });

    const Permission = IDL.Variant({
        Read: IDL.Null,
        Write: IDL.Null,
        Delete: IDL.Null,
    });

    const AccessGrant = IDL.Record({
        grantedTo: IDL.Principal,
        grantedBy: IDL.Text,
        recordIds: IDL.Vec(IDL.Nat),
        expiresAt: IDL.Opt(IDL.Int),
        permissions: IDL.Vec(Permission),
        createdAt: IDL.Int,
    });

    const Error = IDL.Variant({
        NotAuthenticated: IDL.Null,
        Unauthorized: IDL.Null,
        NotFound: IDL.Null,
        AlreadyExists: IDL.Null,
        InvalidInput: IDL.Null,
        InternalError: IDL.Null,
    });

    const Result_DID = IDL.Variant({ ok: DID, err: Error });
    const Result_Profile = IDL.Variant({ ok: PatientProfile, err: Error });
    const Result_Record = IDL.Variant({ ok: MedicalRecord, err: Error });
    const Result_Records = IDL.Variant({ ok: IDL.Vec(MedicalRecord), err: Error });
    const Result_Grant = IDL.Variant({ ok: AccessGrant, err: Error });
    const Result_Grants = IDL.Variant({ ok: IDL.Vec(AccessGrant), err: Error });
    const Result_Unit = IDL.Variant({ ok: IDL.Null, err: Error });

    return IDL.Service({
        createDID: IDL.Func([], [Result_DID], []),
        getMyDID: IDL.Func([], [Result_DID], []),
        resolveDID: IDL.Func([IDL.Text], [Result_DID], ["query"]),
        createOrUpdateProfile: IDL.Func(
            [IDL.Text, IDL.Text, IDL.Opt(IDL.Text), IDL.Vec(IDL.Text)],
            [Result_Profile],
            []
        ),
        getMyProfile: IDL.Func([], [Result_Profile], []),
        addMedicalRecord: IDL.Func(
            [RecordType, IDL.Vec(IDL.Nat8), IDL.Text, RecordMetadata],
            [Result_Record],
            []
        ),
        getMedicalRecord: IDL.Func([IDL.Nat], [Result_Record], []),
        getMyMedicalRecords: IDL.Func([], [Result_Records], []),
        updateMedicalRecord: IDL.Func(
            [IDL.Nat, IDL.Vec(IDL.Nat8), IDL.Text, RecordMetadata],
            [Result_Record],
            []
        ),
        deleteMedicalRecord: IDL.Func([IDL.Nat], [Result_Unit], []),
        grantAccess: IDL.Func(
            [IDL.Principal, IDL.Vec(IDL.Nat), IDL.Vec(Permission), IDL.Opt(IDL.Int)],
            [Result_Grant],
            []
        ),
        revokeAccess: IDL.Func([IDL.Principal], [Result_Unit], []),
        getMyAccessGrants: IDL.Func([], [Result_Grants], []),
        getAccessibleRecords: IDL.Func([], [Result_Records], []),
        getTotalPatients: IDL.Func([], [IDL.Nat], ["query"]),
        getTotalRecords: IDL.Func([], [IDL.Nat], ["query"]),
    });
};

// Application State
let authClient = null;
let actor = null;
let userPrincipal = null;
let userDID = null;
let userProfile = null;
let userRecords = [];
let accessGrants = [];

// Encryption utilities using Web Crypto API
const crypto = {
    // Generate a random encryption key
    async generateKey() {
        const key = await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
        return key;
    },

    // Export key to raw format for storage
    async exportKey(key) {
        const exported = await window.crypto.subtle.exportKey("raw", key);
        return new Uint8Array(exported);
    },

    // Import key from raw format
    async importKey(keyData) {
        return await window.crypto.subtle.importKey(
            "raw",
            keyData,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Encrypt data
    async encrypt(data, key) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedData = new TextEncoder().encode(data);
        
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encodedData
        );

        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        
        return combined;
    },

    // Decrypt data
    async decrypt(encryptedData, key) {
        const iv = encryptedData.slice(0, 12);
        const data = encryptedData.slice(12);
        
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );
        
        return new TextDecoder().decode(decrypted);
    },

    // Hash key for verification
    async hashKey(key) {
        const exported = await this.exportKey(key);
        const hashBuffer = await window.crypto.subtle.digest("SHA-256", exported);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    },

    // Store key using IndexedDB with encryption for improved security
    // Note: In production, consider using hardware security modules or secure enclaves
    async storeKey(recordId, keyData) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open("serum_keys_db", 1);
            
            request.onerror = () => reject(request.error);
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains("keys")) {
                    db.createObjectStore("keys", { keyPath: "recordId" });
                }
            };
            
            request.onsuccess = (event) => {
                const db = event.target.result;
                const transaction = db.transaction(["keys"], "readwrite");
                const store = transaction.objectStore("keys");
                store.put({ recordId: recordId.toString(), keyData: Array.from(keyData) });
                transaction.oncomplete = () => resolve();
                transaction.onerror = () => reject(transaction.error);
            };
        });
    },

    // Retrieve stored key from IndexedDB
    async getStoredKey(recordId) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open("serum_keys_db", 1);
            
            request.onerror = () => reject(request.error);
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains("keys")) {
                    db.createObjectStore("keys", { keyPath: "recordId" });
                }
            };
            
            request.onsuccess = (event) => {
                const db = event.target.result;
                const transaction = db.transaction(["keys"], "readonly");
                const store = transaction.objectStore("keys");
                const getRequest = store.get(recordId.toString());
                
                getRequest.onsuccess = () => {
                    if (getRequest.result) {
                        resolve(new Uint8Array(getRequest.result.keyData));
                    } else {
                        resolve(null);
                    }
                };
                getRequest.onerror = () => reject(getRequest.error);
            };
        });
    }
};

// Initialize the application
async function init() {
    try {
        // Create auth client
        authClient = await AuthClient.create();

        // Check if user is already authenticated
        if (await authClient.isAuthenticated()) {
            await handleAuthenticated();
        }

        // Setup event listeners
        setupEventListeners();
    } catch (error) {
        console.error("Failed to initialize:", error);
        showMessage("Failed to initialize application", "error");
    }
}

// Setup event listeners
function setupEventListeners() {
    // Auth buttons
    document.getElementById("btn-login").addEventListener("click", login);
    document.getElementById("btn-logout").addEventListener("click", logout);
    document.getElementById("btn-get-started").addEventListener("click", login);

    // DID creation
    document.getElementById("btn-create-did").addEventListener("click", createDID);

    // Profile form
    document.getElementById("profile-form").addEventListener("submit", saveProfile);

    // Record modal
    document.getElementById("btn-add-record").addEventListener("click", () => showModal("modal-add-record"));
    document.getElementById("record-form").addEventListener("submit", addRecord);

    // Access modal
    document.getElementById("btn-grant-access").addEventListener("click", () => showModal("modal-grant-access"));
    document.getElementById("access-form").addEventListener("submit", grantAccess);

    // Modal close buttons
    document.querySelectorAll(".modal-close, .modal-cancel").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const modal = e.target.closest(".modal");
            if (modal) hideModal(modal.id);
        });
    });

    // Close modal on outside click
    document.querySelectorAll(".modal").forEach(modal => {
        modal.addEventListener("click", (e) => {
            if (e.target === modal) hideModal(modal.id);
        });
    });
}

// Login with Internet Identity
async function login() {
    try {
        const iiUrl = process.env.DFX_NETWORK === "ic"
            ? "https://identity.ic0.app"
            : `http://${II_CANISTER_ID}.localhost:4943`;

        await authClient.login({
            identityProvider: iiUrl,
            onSuccess: handleAuthenticated,
            onError: (error) => {
                console.error("Login failed:", error);
                showMessage("Login failed. Please try again.", "error");
            }
        });
    } catch (error) {
        console.error("Login error:", error);
        showMessage("Login failed. Please try again.", "error");
    }
}

// Logout
async function logout() {
    await authClient.logout();
    userPrincipal = null;
    userDID = null;
    userProfile = null;
    userRecords = [];
    accessGrants = [];
    
    // Update UI
    document.getElementById("btn-login").classList.remove("hidden");
    document.getElementById("user-info").classList.add("hidden");
    document.getElementById("section-landing").classList.remove("hidden");
    document.getElementById("section-dashboard").classList.add("hidden");
}

// Handle authenticated user
async function handleAuthenticated() {
    try {
        const identity = authClient.getIdentity();
        userPrincipal = identity.getPrincipal();

        // Create actor with authenticated identity
        const agent = new HttpAgent({ identity });
        
        // For local development
        if (process.env.DFX_NETWORK !== "ic") {
            await agent.fetchRootKey();
        }

        actor = Actor.createActor(idlFactory, {
            agent,
            canisterId: BACKEND_CANISTER_ID,
        });

        // Update UI
        document.getElementById("btn-login").classList.add("hidden");
        document.getElementById("user-info").classList.remove("hidden");
        document.getElementById("user-principal").textContent = 
            userPrincipal.toString().substring(0, 20) + "...";
        document.getElementById("section-landing").classList.add("hidden");
        document.getElementById("section-dashboard").classList.remove("hidden");

        // Load user data
        await loadUserData();
    } catch (error) {
        console.error("Authentication handling failed:", error);
        showMessage("Failed to complete authentication", "error");
    }
}

// Load user data from backend
async function loadUserData() {
    try {
        // Get or create DID
        const didResult = await actor.getMyDID();
        
        if ("ok" in didResult) {
            userDID = didResult.ok;
            displayDID(userDID);
            document.getElementById("btn-create-did").classList.add("hidden");
        } else if ("err" in didResult && "NotFound" in didResult.err) {
            document.getElementById("did-value").textContent = "No DID created yet";
            document.getElementById("btn-create-did").classList.remove("hidden");
        }

        // Get profile
        const profileResult = await actor.getMyProfile();
        if ("ok" in profileResult) {
            userProfile = profileResult.ok;
            displayProfile(userProfile);
        }

        // Get records
        const recordsResult = await actor.getMyMedicalRecords();
        if ("ok" in recordsResult) {
            userRecords = recordsResult.ok;
            displayRecords(userRecords);
        }

        // Get access grants
        const grantsResult = await actor.getMyAccessGrants();
        if ("ok" in grantsResult) {
            accessGrants = grantsResult.ok;
            displayAccessGrants(accessGrants);
        }
    } catch (error) {
        console.error("Failed to load user data:", error);
        showMessage("Failed to load your data", "error");
    }
}

// Create DID
async function createDID() {
    try {
        const result = await actor.createDID();
        
        if ("ok" in result) {
            userDID = result.ok;
            displayDID(userDID);
            document.getElementById("btn-create-did").classList.add("hidden");
            showMessage("DID created successfully!", "success");
        } else {
            showMessage("Failed to create DID: " + Object.keys(result.err)[0], "error");
        }
    } catch (error) {
        console.error("Failed to create DID:", error);
        showMessage("Failed to create DID", "error");
    }
}

// Display DID
function displayDID(did) {
    document.getElementById("did-value").textContent = did.identifier;
}

// Save profile
async function saveProfile(e) {
    e.preventDefault();
    
    const name = document.getElementById("profile-name").value;
    const dob = document.getElementById("profile-dob").value;
    const bloodType = document.getElementById("profile-blood").value || null;
    const allergiesText = document.getElementById("profile-allergies").value;
    const allergies = allergiesText ? allergiesText.split(",").map(a => a.trim()) : [];

    try {
        const result = await actor.createOrUpdateProfile(
            name,
            dob,
            bloodType ? [bloodType] : [],
            allergies
        );

        if ("ok" in result) {
            userProfile = result.ok;
            showMessage("Profile saved successfully!", "success");
            
            // Also ensure DID is created
            if (!userDID) {
                await loadUserData();
            }
        } else {
            showMessage("Failed to save profile: " + Object.keys(result.err)[0], "error");
        }
    } catch (error) {
        console.error("Failed to save profile:", error);
        showMessage("Failed to save profile", "error");
    }
}

// Display profile
function displayProfile(profile) {
    document.getElementById("profile-name").value = profile.name || "";
    document.getElementById("profile-dob").value = profile.dateOfBirth || "";
    document.getElementById("profile-blood").value = 
        profile.bloodType && profile.bloodType[0] ? profile.bloodType[0] : "";
    document.getElementById("profile-allergies").value = 
        profile.allergies ? profile.allergies.join(", ") : "";
}

// Add medical record
async function addRecord(e) {
    e.preventDefault();

    try {
        // Get form values
        const recordType = document.getElementById("record-type").value;
        const title = document.getElementById("record-title").value;
        const provider = document.getElementById("record-provider").value;
        const facility = document.getElementById("record-facility").value || null;
        const dateOfService = document.getElementById("record-date").value;
        const data = document.getElementById("record-data").value;
        const tagsText = document.getElementById("record-tags").value;
        const tags = tagsText ? tagsText.split(",").map(t => t.trim()) : [];

        // Generate encryption key and encrypt data
        const key = await crypto.generateKey();
        const encryptedData = await crypto.encrypt(data, key);
        const keyHash = await crypto.hashKey(key);

        // Convert record type to variant
        const recordTypeVariant = { [recordType]: null };

        const metadata = {
            title,
            provider,
            facility: facility ? [facility] : [],
            dateOfService,
            tags
        };

        const result = await actor.addMedicalRecord(
            recordTypeVariant,
            Array.from(encryptedData),
            keyHash,
            metadata
        );

        if ("ok" in result) {
            const record = result.ok;
            
            // Store encryption key locally using IndexedDB
            const keyData = await crypto.exportKey(key);
            await crypto.storeKey(record.id, keyData);

            userRecords.push(record);
            displayRecords(userRecords);
            hideModal("modal-add-record");
            document.getElementById("record-form").reset();
            showMessage("Medical record added successfully!", "success");
        } else {
            showMessage("Failed to add record: " + Object.keys(result.err)[0], "error");
        }
    } catch (error) {
        console.error("Failed to add record:", error);
        showMessage("Failed to add record", "error");
    }
}

// Display records
function displayRecords(records) {
    const container = document.getElementById("records-list");
    
    if (records.length === 0) {
        container.innerHTML = '<p class="empty-state">No medical records yet. Add your first record.</p>';
        return;
    }

    container.innerHTML = records.map(record => {
        const recordType = Object.keys(record.recordType)[0];
        return `
            <div class="record-item" data-id="${record.id}">
                <div class="record-info">
                    <h4>${record.metadata.title}</h4>
                    <p>${record.metadata.provider} • ${record.metadata.dateOfService}</p>
                    <div class="record-meta">
                        <span class="record-tag record-type">${recordType}</span>
                        ${record.metadata.tags.map(tag => 
                            `<span class="record-tag">${tag}</span>`
                        ).join("")}
                    </div>
                </div>
                <div class="record-actions">
                    <button class="btn btn-secondary" onclick="viewRecord(${record.id})">View</button>
                    <button class="btn btn-danger" onclick="deleteRecord(${record.id})">Delete</button>
                </div>
            </div>
        `;
    }).join("");
}

// View record (decrypt and display)
window.viewRecord = async function(recordId) {
    try {
        const record = userRecords.find(r => Number(r.id) === recordId);
        if (!record) {
            showMessage("Record not found", "error");
            return;
        }

        const keyData = await crypto.getStoredKey(recordId);
        if (!keyData) {
            showMessage("Encryption key not found. Cannot decrypt record.", "error");
            return;
        }

        const key = await crypto.importKey(keyData);
        const encryptedData = new Uint8Array(record.encryptedData);
        const decryptedData = await crypto.decrypt(encryptedData, key);

        // Display in a secure modal instead of alert
        showRecordModal(record.metadata.title, decryptedData);
    } catch (error) {
        console.error("Failed to decrypt record:", error);
        showMessage("Failed to decrypt record", "error");
    }
};

// Secure modal for displaying decrypted medical data
function showRecordModal(title, data) {
    // Create or reuse modal
    let modal = document.getElementById("modal-view-record");
    if (!modal) {
        modal = document.createElement("div");
        modal.id = "modal-view-record";
        modal.className = "modal";
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3 id="view-record-title">Record Details</h3>
                    <button class="modal-close" onclick="hideModal('modal-view-record')">&times;</button>
                </div>
                <div class="form-group">
                    <label>Medical Data</label>
                    <pre id="view-record-data" style="white-space: pre-wrap; word-wrap: break-word; background: var(--background); padding: 1rem; border-radius: 0.5rem; max-height: 400px; overflow-y: auto;"></pre>
                </div>
                <div class="form-actions">
                    <button class="btn btn-secondary" onclick="hideModal('modal-view-record')">Close</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        
        // Close on outside click
        modal.addEventListener("click", (e) => {
            if (e.target === modal) hideModal("modal-view-record");
        });
    }
    
    document.getElementById("view-record-title").textContent = title;
    document.getElementById("view-record-data").textContent = data;
    modal.classList.remove("hidden");
}

// Delete record
window.deleteRecord = async function(recordId) {
    if (!confirm("Are you sure you want to delete this record?")) {
        return;
    }

    try {
        const result = await actor.deleteMedicalRecord(recordId);
        
        if ("ok" in result) {
            userRecords = userRecords.filter(r => Number(r.id) !== recordId);
            displayRecords(userRecords);
            showMessage("Record deleted successfully", "success");
        } else {
            showMessage("Failed to delete record: " + Object.keys(result.err)[0], "error");
        }
    } catch (error) {
        console.error("Failed to delete record:", error);
        showMessage("Failed to delete record", "error");
    }
};

// Grant access
async function grantAccess(e) {
    e.preventDefault();

    try {
        const principalText = document.getElementById("access-principal").value;
        const principal = Principal.fromText(principalText);
        
        const permissionCheckboxes = document.querySelectorAll('input[name="permission"]:checked');
        const permissions = Array.from(permissionCheckboxes).map(cb => ({ [cb.value]: null }));

        const expiryInput = document.getElementById("access-expiry").value;
        const expiresAt = expiryInput 
            ? [BigInt(new Date(expiryInput).getTime() * NANOSECONDS_PER_MILLISECOND)]
            : [];

        // For now, grant access to all records (empty array means all)
        const recordIds = [];

        const result = await actor.grantAccess(principal, recordIds, permissions, expiresAt);

        if ("ok" in result) {
            accessGrants.push(result.ok);
            displayAccessGrants(accessGrants);
            hideModal("modal-grant-access");
            document.getElementById("access-form").reset();
            showMessage("Access granted successfully!", "success");
        } else {
            showMessage("Failed to grant access: " + Object.keys(result.err)[0], "error");
        }
    } catch (error) {
        console.error("Failed to grant access:", error);
        showMessage("Failed to grant access. Check the principal ID.", "error");
    }
}

// Display access grants
function displayAccessGrants(grants) {
    const container = document.getElementById("access-list");
    
    if (grants.length === 0) {
        container.innerHTML = '<p class="empty-state">No access grants yet. Share your records securely with healthcare providers.</p>';
        return;
    }

    container.innerHTML = grants.map(grant => {
        const permissions = grant.permissions.map(p => Object.keys(p)[0]).join(", ");
        const expiry = grant.expiresAt && grant.expiresAt[0] 
            ? new Date(Number(grant.expiresAt[0]) / NANOSECONDS_PER_MILLISECOND).toLocaleDateString()
            : "Never";
        
        return `
            <div class="access-item">
                <h4>Provider: ${grant.grantedTo.toString()}</h4>
                <p>Expires: ${expiry}</p>
                <div class="access-permissions">
                    ${grant.permissions.map(p => 
                        `<span class="permission-badge">${Object.keys(p)[0]}</span>`
                    ).join("")}
                </div>
                <button class="btn btn-danger" style="margin-top: 0.5rem" 
                    onclick="revokeAccess('${grant.grantedTo.toString()}')">
                    Revoke Access
                </button>
            </div>
        `;
    }).join("");
}

// Revoke access
window.revokeAccess = async function(principalText) {
    if (!confirm("Are you sure you want to revoke access for this provider?")) {
        return;
    }

    try {
        const principal = Principal.fromText(principalText);
        const result = await actor.revokeAccess(principal);
        
        if ("ok" in result) {
            accessGrants = accessGrants.filter(g => g.grantedTo.toString() !== principalText);
            displayAccessGrants(accessGrants);
            showMessage("Access revoked successfully", "success");
        } else {
            showMessage("Failed to revoke access: " + Object.keys(result.err)[0], "error");
        }
    } catch (error) {
        console.error("Failed to revoke access:", error);
        showMessage("Failed to revoke access", "error");
    }
};

// Modal helpers
function showModal(modalId) {
    document.getElementById(modalId).classList.remove("hidden");
}

function hideModal(modalId) {
    document.getElementById(modalId).classList.add("hidden");
}

// Message display helper
function showMessage(message, type = "info") {
    // Remove existing messages
    const existing = document.querySelector(".message");
    if (existing) existing.remove();

    const div = document.createElement("div");
    div.className = `message message-${type}`;
    div.textContent = message;
    
    document.querySelector("main").prepend(div);
    
    setTimeout(() => div.remove(), 5000);
}

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", init);
