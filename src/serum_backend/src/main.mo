// Serum ICP EHR - Patient DID and Medical Records Management
// This canister implements a decentralized EHR system using Internet Identity

import Principal "mo:base/Principal";
import HashMap "mo:base/HashMap";
import Text "mo:base/Text";
import Nat "mo:base/Nat";
import Time "mo:base/Time";
import Array "mo:base/Array";
import Result "mo:base/Result";
import Iter "mo:base/Iter";
import Blob "mo:base/Blob";
import Option "mo:base/Option";

actor SerumEHR {

    // Type Definitions

    // Decentralized Identifier derived from Internet Identity principal
    public type DID = {
        method: Text;           // "icp" for Internet Computer
        identifier: Text;       // Principal-based unique identifier
        createdAt: Int;         // Timestamp of DID creation
    };

    // Patient profile linked to their DID
    public type PatientProfile = {
        did: DID;
        name: Text;
        dateOfBirth: Text;      // ISO format date
        bloodType: ?Text;
        allergies: [Text];
        createdAt: Int;
        updatedAt: Int;
    };

    // Encrypted medical record
    public type MedicalRecord = {
        id: Nat;
        patientDid: Text;       // Reference to patient's DID
        recordType: RecordType;
        encryptedData: Blob;    // AES-256 encrypted medical data
        encryptionKeyHash: Text; // Hash of the encryption key for verification
        metadata: RecordMetadata;
        createdAt: Int;
        updatedAt: Int;
    };

    // Types of medical records
    public type RecordType = {
        #Diagnosis;
        #Prescription;
        #LabResult;
        #Imaging;
        #Procedure;
        #Vaccination;
        #Allergy;
        #VitalSigns;
        #Other;
    };

    // Metadata for medical records (non-sensitive, unencrypted)
    public type RecordMetadata = {
        title: Text;
        provider: Text;         // Healthcare provider name
        facility: ?Text;        // Healthcare facility
        dateOfService: Text;    // ISO format date
        tags: [Text];
    };

    // Access grant for sharing records with healthcare providers
    public type AccessGrant = {
        grantedTo: Principal;   // Healthcare provider's principal
        grantedBy: Text;        // Patient's DID
        recordIds: [Nat];       // Specific records or empty for all
        expiresAt: ?Int;        // Optional expiration timestamp
        permissions: [Permission];
        createdAt: Int;
    };

    public type Permission = {
        #Read;
        #Write;
        #Delete;
    };

    // Error types
    public type Error = {
        #NotAuthenticated;
        #Unauthorized;
        #NotFound;
        #AlreadyExists;
        #InvalidInput;
        #InternalError;
    };

    // State Variables

    // Mapping from Internet Identity principal to DID
    private stable var didEntries : [(Principal, DID)] = [];
    private var dids = HashMap.HashMap<Principal, DID>(0, Principal.equal, Principal.hash);

    // Mapping from DID identifier to patient profile
    private stable var profileEntries : [(Text, PatientProfile)] = [];
    private var profiles = HashMap.HashMap<Text, PatientProfile>(0, Text.equal, Text.hash);

    // Medical records storage (indexed by record ID)
    private stable var recordEntries : [(Nat, MedicalRecord)] = [];
    private var records = HashMap.HashMap<Nat, MedicalRecord>(0, Nat.equal, natHash);

    // Patient's records index (DID -> record IDs)
    private stable var patientRecordEntries : [(Text, [Nat])] = [];
    private var patientRecords = HashMap.HashMap<Text, [Nat]>(0, Text.equal, Text.hash);

    // Access grants (grantedTo principal -> grants)
    private stable var accessGrantEntries : [(Principal, [AccessGrant])] = [];
    private var accessGrants = HashMap.HashMap<Principal, [AccessGrant]>(0, Principal.equal, Principal.hash);

    // Counter for record IDs
    private stable var nextRecordId : Nat = 1;

    // Helper function for Nat hashing
    private func natHash(n: Nat) : Nat32 {
        Text.hash(Nat.toText(n))
    };

    // System Functions for Upgrade Persistence

    system func preupgrade() {
        didEntries := Iter.toArray(dids.entries());
        profileEntries := Iter.toArray(profiles.entries());
        recordEntries := Iter.toArray(records.entries());
        patientRecordEntries := Iter.toArray(patientRecords.entries());
        accessGrantEntries := Iter.toArray(accessGrants.entries());
    };

    system func postupgrade() {
        dids := HashMap.fromIter<Principal, DID>(didEntries.vals(), didEntries.size(), Principal.equal, Principal.hash);
        profiles := HashMap.fromIter<Text, PatientProfile>(profileEntries.vals(), profileEntries.size(), Text.equal, Text.hash);
        records := HashMap.fromIter<Nat, MedicalRecord>(recordEntries.vals(), recordEntries.size(), Nat.equal, natHash);
        patientRecords := HashMap.fromIter<Text, [Nat]>(patientRecordEntries.vals(), patientRecordEntries.size(), Text.equal, Text.hash);
        accessGrants := HashMap.fromIter<Principal, [AccessGrant]>(accessGrantEntries.vals(), accessGrantEntries.size(), Principal.equal, Principal.hash);
        didEntries := [];
        profileEntries := [];
        recordEntries := [];
        patientRecordEntries := [];
        accessGrantEntries := [];
    };

    // DID Management Functions

    /// Creates a unique DID for the caller derived from their Internet Identity principal
    public shared(msg) func createDID() : async Result.Result<DID, Error> {
        let caller = msg.caller;
        
        // Check if caller is authenticated (not anonymous)
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        // Check if DID already exists for this principal
        switch (dids.get(caller)) {
            case (?existingDid) {
                return #err(#AlreadyExists);
            };
            case null {};
        };

        // Create DID from Internet Identity principal
        let did : DID = {
            method = "icp";
            identifier = "did:icp:" # Principal.toText(caller);
            createdAt = Time.now();
        };

        dids.put(caller, did);
        
        #ok(did)
    };

    /// Gets the DID for the caller
    public shared(msg) func getMyDID() : async Result.Result<DID, Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        switch (dids.get(caller)) {
            case (?did) { #ok(did) };
            case null { #err(#NotFound) };
        }
    };

    /// Resolves a DID identifier to verify it exists
    public query func resolveDID(didIdentifier: Text) : async Result.Result<DID, Error> {
        for ((_, did) in dids.entries()) {
            if (did.identifier == didIdentifier) {
                return #ok(did);
            };
        };
        #err(#NotFound)
    };

    // Patient Profile Functions

    /// Creates or updates patient profile
    public shared(msg) func createOrUpdateProfile(
        name: Text,
        dateOfBirth: Text,
        bloodType: ?Text,
        allergies: [Text]
    ) : async Result.Result<PatientProfile, Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        // Get or create DID
        let did = switch (dids.get(caller)) {
            case (?existingDid) { existingDid };
            case null {
                let newDid : DID = {
                    method = "icp";
                    identifier = "did:icp:" # Principal.toText(caller);
                    createdAt = Time.now();
                };
                dids.put(caller, newDid);
                newDid
            };
        };

        let now = Time.now();
        
        let profile : PatientProfile = switch (profiles.get(did.identifier)) {
            case (?existing) {
                {
                    did = did;
                    name = name;
                    dateOfBirth = dateOfBirth;
                    bloodType = bloodType;
                    allergies = allergies;
                    createdAt = existing.createdAt;
                    updatedAt = now;
                }
            };
            case null {
                {
                    did = did;
                    name = name;
                    dateOfBirth = dateOfBirth;
                    bloodType = bloodType;
                    allergies = allergies;
                    createdAt = now;
                    updatedAt = now;
                }
            };
        };

        profiles.put(did.identifier, profile);
        
        #ok(profile)
    };

    /// Gets the caller's patient profile
    public shared(msg) func getMyProfile() : async Result.Result<PatientProfile, Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        switch (dids.get(caller)) {
            case (?did) {
                switch (profiles.get(did.identifier)) {
                    case (?profile) { #ok(profile) };
                    case null { #err(#NotFound) };
                }
            };
            case null { #err(#NotFound) };
        }
    };

    // Medical Record Functions

    /// Adds an encrypted medical record for the patient
    public shared(msg) func addMedicalRecord(
        recordType: RecordType,
        encryptedData: Blob,
        encryptionKeyHash: Text,
        metadata: RecordMetadata
    ) : async Result.Result<MedicalRecord, Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        // Get caller's DID
        let did = switch (dids.get(caller)) {
            case (?d) { d };
            case null { return #err(#NotFound) };
        };

        let now = Time.now();
        let recordId = nextRecordId;
        nextRecordId += 1;

        let record : MedicalRecord = {
            id = recordId;
            patientDid = did.identifier;
            recordType = recordType;
            encryptedData = encryptedData;
            encryptionKeyHash = encryptionKeyHash;
            metadata = metadata;
            createdAt = now;
            updatedAt = now;
        };

        records.put(recordId, record);

        // Update patient's record index
        let existingRecords = Option.get(patientRecords.get(did.identifier), []);
        patientRecords.put(did.identifier, Array.append(existingRecords, [recordId]));

        #ok(record)
    };

    /// Gets a specific medical record (only accessible by patient or authorized providers)
    public shared(msg) func getMedicalRecord(recordId: Nat) : async Result.Result<MedicalRecord, Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        switch (records.get(recordId)) {
            case (?record) {
                // Check if caller is the patient
                switch (dids.get(caller)) {
                    case (?did) {
                        if (did.identifier == record.patientDid) {
                            return #ok(record);
                        };
                    };
                    case null {};
                };

                // Check if caller has access grant
                if (hasAccess(caller, record.patientDid, recordId, #Read)) {
                    return #ok(record);
                };

                #err(#Unauthorized)
            };
            case null { #err(#NotFound) };
        }
    };

    /// Gets all medical records for the caller (patient)
    public shared(msg) func getMyMedicalRecords() : async Result.Result<[MedicalRecord], Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        switch (dids.get(caller)) {
            case (?did) {
                let recordIds = Option.get(patientRecords.get(did.identifier), []);
                let patientRecordsList = Array.mapFilter<Nat, MedicalRecord>(
                    recordIds,
                    func(id: Nat) : ?MedicalRecord {
                        records.get(id)
                    }
                );
                #ok(patientRecordsList)
            };
            case null { #err(#NotFound) };
        }
    };

    /// Updates an existing medical record
    public shared(msg) func updateMedicalRecord(
        recordId: Nat,
        encryptedData: Blob,
        encryptionKeyHash: Text,
        metadata: RecordMetadata
    ) : async Result.Result<MedicalRecord, Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        switch (records.get(recordId)) {
            case (?existingRecord) {
                // Verify caller owns this record
                switch (dids.get(caller)) {
                    case (?did) {
                        if (did.identifier != existingRecord.patientDid) {
                            // Check for write access
                            if (not hasAccess(caller, existingRecord.patientDid, recordId, #Write)) {
                                return #err(#Unauthorized);
                            };
                        };
                    };
                    case null { return #err(#Unauthorized) };
                };

                let updatedRecord : MedicalRecord = {
                    id = existingRecord.id;
                    patientDid = existingRecord.patientDid;
                    recordType = existingRecord.recordType;
                    encryptedData = encryptedData;
                    encryptionKeyHash = encryptionKeyHash;
                    metadata = metadata;
                    createdAt = existingRecord.createdAt;
                    updatedAt = Time.now();
                };

                records.put(recordId, updatedRecord);
                #ok(updatedRecord)
            };
            case null { #err(#NotFound) };
        }
    };

    /// Deletes a medical record (only by patient or authorized provider with delete permission)
    public shared(msg) func deleteMedicalRecord(recordId: Nat) : async Result.Result<(), Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        switch (records.get(recordId)) {
            case (?existingRecord) {
                // Verify caller owns this record or has delete permission
                switch (dids.get(caller)) {
                    case (?did) {
                        if (did.identifier != existingRecord.patientDid) {
                            if (not hasAccess(caller, existingRecord.patientDid, recordId, #Delete)) {
                                return #err(#Unauthorized);
                            };
                        };
                        
                        // Remove from records
                        records.delete(recordId);
                        
                        // Update patient's record index
                        let currentRecords = Option.get(patientRecords.get(existingRecord.patientDid), []);
                        let filteredRecords = Array.filter<Nat>(
                            currentRecords,
                            func(id: Nat) : Bool { id != recordId }
                        );
                        patientRecords.put(existingRecord.patientDid, filteredRecords);
                        
                        #ok(())
                    };
                    case null { #err(#Unauthorized) };
                }
            };
            case null { #err(#NotFound) };
        }
    };

    // Access Control Functions

    /// Grants access to a healthcare provider for specific records
    public shared(msg) func grantAccess(
        providerPrincipal: Principal,
        recordIds: [Nat],
        permissions: [Permission],
        expiresAt: ?Int
    ) : async Result.Result<AccessGrant, Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        // Get caller's DID
        let did = switch (dids.get(caller)) {
            case (?d) { d };
            case null { return #err(#NotFound) };
        };

        // Verify caller owns the records
        for (recordId in recordIds.vals()) {
            switch (records.get(recordId)) {
                case (?record) {
                    if (record.patientDid != did.identifier) {
                        return #err(#Unauthorized);
                    };
                };
                case null { return #err(#NotFound) };
            };
        };

        let grant : AccessGrant = {
            grantedTo = providerPrincipal;
            grantedBy = did.identifier;
            recordIds = recordIds;
            expiresAt = expiresAt;
            permissions = permissions;
            createdAt = Time.now();
        };

        let existingGrants = Option.get(accessGrants.get(providerPrincipal), []);
        accessGrants.put(providerPrincipal, Array.append(existingGrants, [grant]));

        #ok(grant)
    };

    /// Revokes all access grants for a specific provider
    public shared(msg) func revokeAccess(providerPrincipal: Principal) : async Result.Result<(), Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        let did = switch (dids.get(caller)) {
            case (?d) { d };
            case null { return #err(#NotFound) };
        };

        switch (accessGrants.get(providerPrincipal)) {
            case (?grants) {
                let filteredGrants = Array.filter<AccessGrant>(
                    grants,
                    func(grant: AccessGrant) : Bool {
                        grant.grantedBy != did.identifier
                    }
                );
                accessGrants.put(providerPrincipal, filteredGrants);
                #ok(())
            };
            case null { #ok(()) };
        }
    };

    /// Gets all access grants made by the caller
    public shared(msg) func getMyAccessGrants() : async Result.Result<[AccessGrant], Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        let did = switch (dids.get(caller)) {
            case (?d) { d };
            case null { return #err(#NotFound) };
        };

        var myGrants : [AccessGrant] = [];
        
        for ((_, grants) in accessGrants.entries()) {
            for (grant in grants.vals()) {
                if (grant.grantedBy == did.identifier) {
                    myGrants := Array.append(myGrants, [grant]);
                };
            };
        };

        #ok(myGrants)
    };

    /// Gets records accessible to the caller as a healthcare provider
    public shared(msg) func getAccessibleRecords() : async Result.Result<[MedicalRecord], Error> {
        let caller = msg.caller;
        
        if (Principal.isAnonymous(caller)) {
            return #err(#NotAuthenticated);
        };

        switch (accessGrants.get(caller)) {
            case (?grants) {
                var accessibleRecords : [MedicalRecord] = [];
                let now = Time.now();
                
                for (grant in grants.vals()) {
                    // Check if grant is still valid
                    let isValid = switch (grant.expiresAt) {
                        case (?expiry) { expiry > now };
                        case null { true };
                    };
                    
                    if (isValid and hasPermission(grant.permissions, #Read)) {
                        if (grant.recordIds.size() == 0) {
                            // Access to all patient records
                            let patientRecordIds = Option.get(patientRecords.get(grant.grantedBy), []);
                            for (recordId in patientRecordIds.vals()) {
                                switch (records.get(recordId)) {
                                    case (?record) {
                                        accessibleRecords := Array.append(accessibleRecords, [record]);
                                    };
                                    case null {};
                                };
                            };
                        } else {
                            // Access to specific records
                            for (recordId in grant.recordIds.vals()) {
                                switch (records.get(recordId)) {
                                    case (?record) {
                                        accessibleRecords := Array.append(accessibleRecords, [record]);
                                    };
                                    case null {};
                                };
                            };
                        };
                    };
                };
                
                #ok(accessibleRecords)
            };
            case null { #ok([]) };
        }
    };

    // Helper Functions

    /// Checks if a principal has access to a specific record with given permission
    private func hasAccess(principal: Principal, patientDid: Text, recordId: Nat, permission: Permission) : Bool {
        switch (accessGrants.get(principal)) {
            case (?grants) {
                let now = Time.now();
                for (grant in grants.vals()) {
                    if (grant.grantedBy == patientDid) {
                        // Check expiration
                        let isValid = switch (grant.expiresAt) {
                            case (?expiry) { expiry > now };
                            case null { true };
                        };
                        
                        if (isValid and hasPermission(grant.permissions, permission)) {
                            // Check if access is to all records or specific record
                            if (grant.recordIds.size() == 0) {
                                return true;
                            };
                            for (grantedRecordId in grant.recordIds.vals()) {
                                if (grantedRecordId == recordId) {
                                    return true;
                                };
                            };
                        };
                    };
                };
                false
            };
            case null { false };
        }
    };

    /// Checks if a permission is in the list of permissions
    private func hasPermission(permissions: [Permission], required: Permission) : Bool {
        for (p in permissions.vals()) {
            switch (p, required) {
                case (#Read, #Read) { return true };
                case (#Write, #Write) { return true };
                case (#Delete, #Delete) { return true };
                case _ {};
            };
        };
        false
    };

    // Query Functions for Statistics

    /// Gets the total number of patients registered
    public query func getTotalPatients() : async Nat {
        dids.size()
    };

    /// Gets the total number of medical records
    public query func getTotalRecords() : async Nat {
        records.size()
    };
}
