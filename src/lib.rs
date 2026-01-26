use std::collections::BTreeMap;
use std::vec::Vec;
use std::fmt;
use std::error::Error;
 
/// Compilation status indicating pass or fail verdict.
/// Uses SCREAMING_CASE variants per Rust enum conventions for C-style enums.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompilationStatus {
    Pass,
    Fail,
}

impl fmt::Display for CompilationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompilationStatus::Pass => write!(f, "PASS"),
            CompilationStatus::Fail => write!(f, "FAIL"),
        }
    }
}

/// Error types for compilation failures with structured categorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompilationError {
    EmptyInput,
    NoClauses,
    IntentNormalizationFailed { reason: String },
    ModalLanguageDetected { clause_index: usize, clause: String, modal_word: String },
    MissingActionVerb { clause_index: usize, clause: String },
    AmbiguousMultiAction { clause_index: usize, clause: String },
    MissingPrincipal { clause_index: usize, clause: String },
    MissingMeasurementUnit { clause_index: usize, clause: String },
    MissingCostSubject { clause_index: usize, clause: String },
    InternalError { context: String },
}

impl fmt::Display for CompilationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompilationError::EmptyInput => write!(f, "Empty policy input"),
            CompilationError::NoClauses => write!(f, "No valid clauses found"),
            CompilationError::IntentNormalizationFailed { reason } => {
                write!(f, "Intent normalization failed: {}", reason)
            }
            CompilationError::ModalLanguageDetected { clause_index, clause, modal_word } => {
                write!(f, "Clause {} contains modal language '{}': '{}'", clause_index, modal_word, clause)
            }
            CompilationError::MissingActionVerb { clause_index, clause } => {
                write!(f, "Clause {} missing action verb: '{}'", clause_index, clause)
            }
            CompilationError::AmbiguousMultiAction { clause_index, clause } => {
                write!(f, "Clause {} has ambiguous multi-action without ordering: '{}'", clause_index, clause)
            }
            CompilationError::MissingPrincipal { clause_index, clause } => {
                write!(f, "Clause {} missing explicit principal: '{}'", clause_index, clause)
            }
            CompilationError::MissingMeasurementUnit { clause_index, clause } => {
                write!(f, "Clause {} mentions cost but no explicit measurement unit: '{}'", clause_index, clause)
            }
            CompilationError::MissingCostSubject { clause_index, clause } => {
                write!(f, "Clause {} mentions cost but no attribution subject: '{}'", clause_index, clause)
            }
            CompilationError::InternalError { context } => {
                write!(f, "Internal error: {}", context)
            }
        }
    }
}

impl Error for CompilationError {}

/// Known principals for zero-trust authority validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Principal {
    System,
    User,
    Service,
}

impl Principal {
    /// Returns the canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Principal::System => "SYSTEM",
            Principal::User => "USER",
            Principal::Service => "SERVICE",
        }
    }

    /// Attempts to parse a principal from text using word boundary detection.
    pub fn from_clause(clause: &str) -> Option<Self> {
        let clause_upper = clause.to_uppercase();
        let tokens: Vec<&str> = clause_upper.split_whitespace()
            .map(|t| t.trim_matches(|c: char| !c.is_alphanumeric()))
            .collect();
        
        // Check tokens for exact matches (word boundary detection)
        for token in &tokens {
            match *token {
                "SYSTEM" => return Some(Principal::System),
                "USER" => return Some(Principal::User),
                "SERVICE" => return Some(Principal::Service),
                _ => continue,
            }
        }
        None
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Known measurement units for ICAE cost constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MeasurementUnit {
    Usd,
    Eur,
    Gbp,
    Tokens,
    Bytes,
    Requests,
    Hours,
}

impl MeasurementUnit {
    /// Returns the canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            MeasurementUnit::Usd => "USD",
            MeasurementUnit::Eur => "EUR",
            MeasurementUnit::Gbp => "GBP",
            MeasurementUnit::Tokens => "tokens",
            MeasurementUnit::Bytes => "bytes",
            MeasurementUnit::Requests => "requests",
            MeasurementUnit::Hours => "hours",
        }
    }

    /// Attempts to parse a measurement unit from text.
    pub fn from_clause(clause: &str) -> Option<Self> {
        let clause_lower = clause.to_lowercase();
        
        // Check for currency symbols first - these are NOT valid units
        if ["$", "€", "£", "¥", "â‚¬", "Â£", "Â¥"].iter().any(|s| clause.contains(s)) {
            return None;
        }
        
        // Check for explicit unit names (case-insensitive)
        if clause_lower.contains("usd") { return Some(MeasurementUnit::Usd); }
        if clause_lower.contains("eur") { return Some(MeasurementUnit::Eur); }
        if clause_lower.contains("gbp") { return Some(MeasurementUnit::Gbp); }
        if clause_lower.contains("tokens") { return Some(MeasurementUnit::Tokens); }
        if clause_lower.contains("bytes") { return Some(MeasurementUnit::Bytes); }
        if clause_lower.contains("requests") { return Some(MeasurementUnit::Requests); }
        if clause_lower.contains("hours") { return Some(MeasurementUnit::Hours); }
        
        None
    }
}

impl fmt::Display for MeasurementUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Modal words that indicate non-deterministic policy language.
const MODAL_WORDS: &[&str] = &["should", "may", "where reasonable", "as appropriate", "could", "might", "possibly"];

/// Action verbs required for valid policy clauses.
const ACTION_VERBS: &[&str] = &["must", "shall", "require", "log", "audit", "record", "deny", "allow", "enforce", "track", "exceed"];

/// Cost indicator terms that trigger ICAE constraint validation.
const COST_INDICATORS: &[&str] = &["cost", "spend", "usage", "quota", "resource consumption", "externality", "budget", "expense"];

#[derive(Debug, Clone)]
pub struct IntentNormalization {
    pub clauses: Vec<String>,
    pub assumptions: Vec<String>,
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DIOInvariant {
    pub id: String,
    pub description: String,
    pub clause_index: usize,
    pub failure_signal: String,
}

#[derive(Debug, Clone)]
pub struct ZTAuthority {
    pub id: String,
    pub principal: Principal,
    pub scope: String,
    pub clause_index: usize,
    pub delegation_rules: Vec<String>,
    pub revocation_triggers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ICAECostConstraint {
    pub id: String,
    pub subject: String,
    pub measurement_unit: MeasurementUnit,
    pub clause_index: usize,
    pub ceiling: Option<f64>,
    pub externalities: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TraceabilityEntry {
    pub clause_id: String,
    pub clause_index: usize,
    pub clause_text: String,
    pub invariant_ids: Vec<String>,
    pub authority_ids: Vec<String>,
    pub cost_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CompilationResult {
    pub intent_normalization: IntentNormalization,
    pub dio_invariants: Vec<DIOInvariant>,
    pub zt_authority_graph: Vec<ZTAuthority>,
    pub icae_constraints: Vec<ICAECostConstraint>,
    pub traceability_map: Vec<TraceabilityEntry>,
    pub verdict: CompilationStatus,
    pub errors: Vec<CompilationError>,
    /// Legacy field for backward compatibility - use errors instead
    #[deprecated(note = "Use errors field instead for structured error handling")]
    pub failures: Vec<String>,
}

impl CompilationResult {
    /// Returns true if compilation succeeded.
    pub fn is_success(&self) -> bool {
        self.verdict == CompilationStatus::Pass
    }

    /// Returns formatted error messages.
    pub fn error_messages(&self) -> Vec<String> {
        self.errors.iter().map(|e| e.to_string()).collect()
    }
}

/// Policy compiler with deterministic output guarantees.
/// 
/// # Determinism
/// Given identical input, the compiler produces identical output. All internal
/// collections use deterministic ordering (BTreeMap over HashMap for iteration).
#[derive(Debug, Clone, Default)]
pub struct PolicyCompiler {
    _private: (),  // Prevents direct construction, enforces ::new()
}

impl PolicyCompiler {
    /// Creates a new PolicyCompiler instance.
    pub fn new() -> Self {
        PolicyCompiler {
            _private: (),
        }
    }

    /// Compiles a policy string into governance artifacts.
    /// 
    /// # Arguments
    /// * `policy_input` - The policy text to compile
    /// 
    /// # Returns
    /// A CompilationResult containing all artifacts or error details.
    /// 
    /// # Thread Safety
    /// This method is stateless and inherently thread-safe.
    /// Multiple threads can call compile() concurrently without synchronization.
    pub fn compile(&self, policy_input: &str) -> CompilationResult {
        let policy_text = policy_input.trim().to_string();
        if policy_text.is_empty() {
            return Self::fail_with_error(CompilationError::EmptyInput);
        }
        // Local state for assumptions and exclusions
        let mut assumptions = Vec::new();
        let mut exclusions = Vec::new();


        // Parse clauses
        let clauses = Self::parse_clauses(&policy_text);
        if clauses.is_empty() {
            return Self::fail_with_error(CompilationError::NoClauses);
        }

        // Normalize intent
        let norm = match Self::normalize_intent(&clauses, &mut assumptions, &mut exclusions) {
            Ok(n) => n,
            Err(e) => return Self::fail_with_error(e),
        };

        // Build artifact maps indexed by clause index using BTreeMap for deterministic iteration
        let mut dio_by_clause: BTreeMap<usize, Vec<DIOInvariant>> = BTreeMap::new();
        let mut auth_by_clause: BTreeMap<usize, Vec<ZTAuthority>> = BTreeMap::new();
        let mut cost_by_clause: BTreeMap<usize, Vec<ICAECostConstraint>> = BTreeMap::new();

        // Initialize all clause indices
        for i in 0..clauses.len() {
            dio_by_clause.insert(i, Vec::new());
            auth_by_clause.insert(i, Vec::new());
            cost_by_clause.insert(i, Vec::new());
        }

        // Compile artifacts - each step is deterministic
        Self::compile_dio_invariants(&clauses, &mut dio_by_clause);
        
        let auth_errors = Self::compile_zt_authority(&clauses, &mut auth_by_clause);
        if !auth_errors.is_empty() {
            return Self::fail_with_errors(auth_errors);
        }

        let cost_errors = Self::compile_icae_constraints(&clauses, &mut cost_by_clause);
        if !cost_errors.is_empty() {
            return Self::fail_with_errors(cost_errors);
        }

        // Flatten artifacts in deterministic clause order
        let mut flattened_dio: Vec<DIOInvariant> = Vec::new();
        let mut flattened_auth: Vec<ZTAuthority> = Vec::new();
        let mut flattened_cost: Vec<ICAECostConstraint> = Vec::new();

        for i in 0..clauses.len() {
            if let Some(invariants) = dio_by_clause.get(&i) {
                flattened_dio.extend(invariants.clone());
            }
            if let Some(authorities) = auth_by_clause.get(&i) {
                flattened_auth.extend(authorities.clone());
            }
            if let Some(constraints) = cost_by_clause.get(&i) {
                flattened_cost.extend(constraints.clone());
            }
        }

        let traceability_map = Self::build_traceability_map(
            &clauses,
            &dio_by_clause,
            &auth_by_clause,
            &cost_by_clause
        );

        CompilationResult {
            intent_normalization: norm,
            dio_invariants: flattened_dio,
            zt_authority_graph: flattened_auth,
            icae_constraints: flattened_cost,
            traceability_map,
            verdict: CompilationStatus::Pass,
            errors: Vec::new(),
            #[allow(deprecated)]
            failures: Vec::new(),
        }
    }

    /// Parses policy text into individual clauses.
    /// Uses period as delimiter with whitespace normalization.
    fn parse_clauses(text: &str) -> Vec<String> {
        text.split_terminator('.')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Normalizes intent by validating clause structure and extracting assumptions/exclusions.
    fn normalize_intent(
        clauses: &[String],
        assumptions: &mut Vec<String>,
        exclusions: &mut Vec<String>,
    ) -> Result<IntentNormalization, CompilationError> {
        // Check for modal/discretionary language
        for (i, clause) in clauses.iter().enumerate() {
            let clause_lower = clause.to_lowercase();
            for modal_word in MODAL_WORDS {
                if clause_lower.contains(modal_word) {
                    return Err(CompilationError::ModalLanguageDetected {
                        clause_index: i,
                        clause: clause.clone(),
                        modal_word: modal_word.to_string(),
                    });
                }
            }
        }

        // Check for atomic clauses
        for (i, clause) in clauses.iter().enumerate() {
            let clause_lower = clause.to_lowercase();
            let has_action = ACTION_VERBS.iter().any(|verb| clause_lower.contains(verb));
            if !has_action {
                return Err(CompilationError::MissingActionVerb {
                    clause_index: i,
                    clause: clause.clone(),
                });
            }
        }

        // Check for multiple actions without ordering
        for (i, clause) in clauses.iter().enumerate() {
            let clause_lower = clause.to_lowercase();
            // Check for conjunctions that indicate multiple unordered actions
            if (clause_lower.contains(" and ") || clause_lower.contains(" or ")) 
                && !clause_lower.contains("then")  // Allow ordered sequences
                && !clause_lower.contains("before") 
                && !clause_lower.contains("after") {
                return Err(CompilationError::AmbiguousMultiAction {
                    clause_index: i,
                    clause: clause.clone(),
                });
            }
        }

        assumptions.clear();
        exclusions.clear();

        // Extract assumptions and exclusions from clauses
        for clause in clauses {
            let clause_lower = clause.to_lowercase();
            if clause_lower.contains("assumes") || clause_lower.contains("assuming") {
                assumptions.push(clause.clone());
            }
            if clause_lower.contains("except") || clause_lower.contains("exclude") || clause_lower.contains("unless") {
                exclusions.push(clause.clone());
            }
        }

        Ok(IntentNormalization {
            clauses: clauses.to_vec(),
            assumptions: assumptions.clone(),
            exclusions: exclusions.clone(),
        })
    }

    /// Compiles DIO invariants for each clause.
    fn compile_dio_invariants(clauses: &[String], dio_by_clause: &mut BTreeMap<usize, Vec<DIOInvariant>>) {
        for (i, clause) in clauses.iter().enumerate() {
            let invariant_id = format!("dio_{}", i);
            let truncated_clause = Self::truncate_clause(clause, 50);
            let description = format!("Enforce policy clause: {}", truncated_clause);
            let failure_signal = format!("VIOLATION_DIO_{}", i);
            
            let invariant = DIOInvariant {
                id: invariant_id.clone(),
                description,
                clause_index: i,
                failure_signal,
            };
            
            if let Some(list) = dio_by_clause.get_mut(&i) {
                list.push(invariant);
            }
        }
    }

    /// Compiles zero-trust authority graph for each clause.
    fn compile_zt_authority(clauses: &[String], auth_by_clause: &mut BTreeMap<usize, Vec<ZTAuthority>>) -> Vec<CompilationError> {
        let mut errors = Vec::new();

        for (i, clause) in clauses.iter().enumerate() {
            match Principal::from_clause(clause) {
                Some(principal) => {
                    let authority_id = format!("zt_auth_{}", i);
                    let scope = format!("scope_{}", i);
                    let truncated_clause = Self::truncate_clause(clause, 30);
                    
                    let delegation_rules = vec![
                        format!("Delegation requires explicit {} approval for: {}", principal, truncated_clause)
                    ];
                    let revocation_triggers = vec![
                        format!("Revoke on policy change affecting: {}", truncated_clause)
                    ];
                    
                    let authority = ZTAuthority {
                        id: authority_id,
                        principal,
                        scope,
                        clause_index: i,
                        delegation_rules,
                        revocation_triggers,
                    };
                    
                    if let Some(list) = auth_by_clause.get_mut(&i) {
                        list.push(authority);
                    }
                }
                None => {
                    errors.push(CompilationError::MissingPrincipal {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                }
            }
        }
        
        errors
    }

    /// Compiles ICAE cost constraints for clauses mentioning cost.
    fn compile_icae_constraints(clauses: &[String], cost_by_clause: &mut BTreeMap<usize, Vec<ICAECostConstraint>>) -> Vec<CompilationError> {
        let mut errors = Vec::new();

        for (i, clause) in clauses.iter().enumerate() {
            let clause_lower = clause.to_lowercase();
            let has_cost_mention = COST_INDICATORS.iter().any(|ind| clause_lower.contains(ind));

            if !has_cost_mention {
                continue;
            }

            let subject = match Self::extract_subject(clause) {
                Some(s) => s,
                None => {
                    errors.push(CompilationError::MissingCostSubject {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                    continue;
                }
            };

            let measurement_unit = match MeasurementUnit::from_clause(clause) {
                Some(u) => u,
                None => {
                    errors.push(CompilationError::MissingMeasurementUnit {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                    continue;
                }
            };

            let constraint_id = format!("icae_{}", i);
            let truncated_clause = Self::truncate_clause(clause, 30);
            let externalities = vec![format!("External cost from: {}", truncated_clause)];

            let constraint = ICAECostConstraint {
                id: constraint_id,
                subject,
                measurement_unit,
                clause_index: i,
                ceiling: None,
                externalities,
            };

            if let Some(list) = cost_by_clause.get_mut(&i) {
                list.push(constraint);
            }
        }

        errors
    }

    /// Extracts cost attribution subject from clause.
    fn extract_subject(clause: &str) -> Option<String> {
        let stop_words: &[&str] = &[
            "cost", "spend", "usage", "quota", "the", "a", "an", "of", "for",
            "per", "must", "shall", "cannot", "exceed", "all", "no", "be", "by",
            "system", "user", "service"
        ];
        
        for word in clause.split_whitespace() {
            let clean_word = word.trim_matches(|c: char| !c.is_alphanumeric());
            let lower = clean_word.to_lowercase();
            
            if clean_word.len() > 3 && !stop_words.contains(&lower.as_str()) {
                return Some(clean_word.to_string());
            }
        }
        None
    }

    /// Builds traceability map linking clauses to artifacts.
    fn build_traceability_map(
        clauses: &[String],
        dio_by_clause: &BTreeMap<usize, Vec<DIOInvariant>>,
        auth_by_clause: &BTreeMap<usize, Vec<ZTAuthority>>,
        cost_by_clause: &BTreeMap<usize, Vec<ICAECostConstraint>>,
    ) -> Vec<TraceabilityEntry> {
        let mut entries = Vec::new();

        for i in 0..clauses.len() {
            let invariant_ids: Vec<String> = dio_by_clause
                .get(&i)
                .map(|v| v.iter().map(|inv| inv.id.clone()).collect())
                .unwrap_or_default();
            
            let authority_ids: Vec<String> = auth_by_clause
                .get(&i)
                .map(|v| v.iter().map(|auth| auth.id.clone()).collect())
                .unwrap_or_default();
            
            let cost_ids: Vec<String> = cost_by_clause
                .get(&i)
                .map(|v| v.iter().map(|cost| cost.id.clone()).collect())
                .unwrap_or_default();

            entries.push(TraceabilityEntry {
                clause_id: format!("clause_{}", i),
                clause_index: i,
                clause_text: clauses.get(i).cloned().unwrap_or_default(),
                invariant_ids,
                authority_ids,
                cost_ids,
            });
        }

        entries
    }

    /// Truncates clause text to specified length with ellipsis.
    fn truncate_clause(clause: &str, max_len: usize) -> String {
        if clause.len() <= max_len {
            clause.to_string()
        } else {
            format!("{}...", &clause[..max_len])
        }
    }

    /// Creates a failed compilation result with a single error.
    fn fail_with_error(error: CompilationError) -> CompilationResult {
        Self::fail_with_errors(vec![error])
    }

    /// Creates a failed compilation result with multiple errors.
    fn fail_with_errors(errors: Vec<CompilationError>) -> CompilationResult {
        #[allow(deprecated)]
        let failures: Vec<String> = errors.iter().map(|e| e.to_string()).collect();

        CompilationResult {
            intent_normalization: IntentNormalization {
                clauses: Vec::new(),
                assumptions: Vec::new(),
                exclusions: Vec::new(),
            },
            dio_invariants: Vec::new(),
            zt_authority_graph: Vec::new(),
            icae_constraints: Vec::new(),
            traceability_map: Vec::new(),
            verdict: CompilationStatus::Fail,
            errors,
            failures,
        }
    }
}


#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_principal_from_clause() {
        assert_eq!(Principal::from_clause("by SYSTEM"), Some(Principal::System));
        assert_eq!(Principal::from_clause("by USER"), Some(Principal::User));
        assert_eq!(Principal::from_clause("by SERVICE"), Some(Principal::Service));
        assert_eq!(Principal::from_clause("by nobody"), None);
        // Word boundary test
        assert_eq!(Principal::from_clause("SYSTEMWIDE"), None);
    }

    #[test]
    fn test_measurement_unit_from_clause() {
        assert_eq!(MeasurementUnit::from_clause("1000 USD"), Some(MeasurementUnit::Usd));
        assert_eq!(MeasurementUnit::from_clause("1000 tokens"), Some(MeasurementUnit::Tokens));
        assert_eq!(MeasurementUnit::from_clause("$1000"), None); // Symbol rejected
        assert_eq!(MeasurementUnit::from_clause("1000 widgets"), None);
    }

    #[test]
    fn test_compilation_error_display() {
        let err = CompilationError::EmptyInput;
        assert_eq!(err.to_string(), "Empty policy input");
        
        let err = CompilationError::ModalLanguageDetected {
            clause_index: 0,
            clause: "should log".to_string(),
            modal_word: "should".to_string(),
        };
        assert!(err.to_string().contains("modal language"));
    }

    #[test]
    fn test_truncate_clause_short() {
        let result = PolicyCompiler::truncate_clause("short", 10);
        assert_eq!(result, "short");
    }

    #[test]
    fn test_truncate_clause_exact() {
        let result = PolicyCompiler::truncate_clause("exactly10!", 10);
        assert_eq!(result, "exactly10!");
    }

    #[test]
    fn test_truncate_clause_long() {
        let result = PolicyCompiler::truncate_clause("this is a very long clause", 10);
        assert_eq!(result, "this is a ...");
    }
}

// Note: Re-exports removed - users should use fully qualified CompilationStatus::Pass/Fail