use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::vec::Vec;

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
    IntentNormalizationFailed {
        reason: String,
    },
    ModalLanguageDetected {
        clause_index: usize,
        clause: String,
        modal_word: String,
    },
    MissingActionVerb {
        clause_index: usize,
        clause: String,
    },
    AmbiguousMultiAction {
        clause_index: usize,
        clause: String,
    },
    MissingPrincipal {
        clause_index: usize,
        clause: String,
    },
    AmbiguousPrincipal {
        clause_index: usize,
        clause: String,
    },
    MissingMeasurementUnit {
        clause_index: usize,
        clause: String,
    },
    AmbiguousMeasurementUnit {
        clause_index: usize,
        clause: String,
    },
    MissingCostSubject {
        clause_index: usize,
        clause: String,
    },
    AmbiguousCostSubject {
        clause_index: usize,
        clause: String,
    },
    InvalidCeiling {
        clause_index: usize,
        clause: String,
        value: String,
    },
    InternalError {
        context: String,
    },
}

impl fmt::Display for CompilationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompilationError::EmptyInput => write!(f, "Empty policy input"),
            CompilationError::NoClauses => write!(f, "No valid clauses found"),
            CompilationError::IntentNormalizationFailed { reason } => {
                write!(f, "Intent normalization failed: {}", reason)
            }
            CompilationError::ModalLanguageDetected {
                clause_index,
                clause,
                modal_word,
            } => {
                write!(
                    f,
                    "Clause {} contains modal language '{}': '{}'",
                    clause_index, modal_word, clause
                )
            }
            CompilationError::MissingActionVerb {
                clause_index,
                clause,
            } => {
                write!(
                    f,
                    "Clause {} missing action verb: '{}'",
                    clause_index, clause
                )
            }
            CompilationError::AmbiguousMultiAction {
                clause_index,
                clause,
            } => {
                write!(
                    f,
                    "Clause {} has ambiguous multi-action without ordering: '{}'",
                    clause_index, clause
                )
            }
            CompilationError::MissingPrincipal {
                clause_index,
                clause,
            } => {
                write!(
                    f,
                    "Clause {} missing explicit principal: '{}'",
                    clause_index, clause
                )
            }
            CompilationError::AmbiguousPrincipal {
                clause_index,
                clause,
            } => {
                write!(
                    f,
                    "Clause {} contains ambiguous authority principals: '{}'",
                    clause_index, clause
                )
            }
            CompilationError::MissingMeasurementUnit {
                clause_index,
                clause,
            } => {
                write!(
                    f,
                    "Clause {} mentions cost but no explicit measurement unit: '{}'",
                    clause_index, clause
                )
            }
            CompilationError::AmbiguousMeasurementUnit {
                clause_index,
                clause,
            } => {
                write!(
                    f,
                    "Clause {} contains multiple measurement units: '{}'",
                    clause_index, clause
                )
            }
            CompilationError::MissingCostSubject {
                clause_index,
                clause,
            } => {
                write!(
                    f,
                    "Clause {} mentions cost but no attribution subject: '{}'",
                    clause_index, clause
                )
            }
            CompilationError::AmbiguousCostSubject {
                clause_index,
                clause,
            } => {
                write!(
                    f,
                    "Clause {} contains multiple cost subjects or indicators: '{}'",
                    clause_index, clause
                )
            }
            CompilationError::InvalidCeiling {
                clause_index,
                clause,
                value,
            } => {
                write!(
                    f,
                    "Clause {} contains invalid cost ceiling '{}': '{}'",
                    clause_index, value, clause
                )
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrincipalResolution {
    Unique(Principal),
    Missing,
    Ambiguous,
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
        match resolve_principal(clause) {
            PrincipalResolution::Unique(principal) => Some(principal),
            PrincipalResolution::Missing | PrincipalResolution::Ambiguous => None,
        }
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
        let units = measurement_units_from_clause(clause);
        if units.len() == 1 {
            units.first().copied()
        } else {
            None
        }
    }
}

impl fmt::Display for MeasurementUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Modal words that indicate non-deterministic policy language.
const MODAL_WORDS: &[&str] = &[
    "should",
    "may",
    "can",
    "where reasonable",
    "as appropriate",
    "could",
    "might",
    "possibly",
];

/// Action verbs required for valid policy clauses.
const ACTION_VERBS: &[&str] = &[
    "require",
    "log",
    "audit",
    "record",
    "deny",
    "allow",
    "enforce",
    "track",
    "exceed",
    "delegate",
    "revoke",
    "approve",
    "required",
    "logged",
    "audited",
    "recorded",
    "denied",
    "allowed",
    "enforced",
    "tracked",
    "delegated",
    "revoked",
    "approved",
    "limited",
    "capped",
];

const ACTION_ORDERING_WORDS: &[&str] = &["then", "before", "after"];

/// Cost indicator terms that trigger ICAE constraint validation.
const COST_INDICATORS: &[&str] = &[
    "cost",
    "costs",
    "spend",
    "spends",
    "usage",
    "usages",
    "quota",
    "quotas",
    "resource consumption",
    "externality",
    "budget",
    "budgets",
    "expense",
    "expenses",
    "fee",
    "fees",
    "price",
    "prices",
    "charge",
    "charges",
    "externalities",
    "limit",
    "limits",
    "cap",
    "caps",
    "ceiling",
    "ceilings",
    "maximum",
    "maximums",
];

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
    _private: (), // Prevents direct construction, enforces ::new()
}

impl PolicyCompiler {
    /// Creates a new PolicyCompiler instance.
    pub fn new() -> Self {
        PolicyCompiler { _private: () }
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
            &cost_by_clause,
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
    /// Uses non-decimal periods as delimiters with whitespace normalization.
    fn parse_clauses(text: &str) -> Vec<String> {
        let characters: Vec<char> = text.chars().collect();
        let mut clauses = Vec::new();
        let mut current = String::new();

        for (index, character) in characters.iter().enumerate() {
            let is_decimal_point = *character == '.'
                && index > 0
                && index + 1 < characters.len()
                && characters[index - 1].is_ascii_digit()
                && characters[index + 1].is_ascii_digit();

            if *character == '.' && !is_decimal_point {
                let clause = current.trim();
                if !clause.is_empty() {
                    clauses.push(clause.to_string());
                }
                current.clear();
            } else {
                current.push(*character);
            }
        }

        let clause = current.trim();
        if !clause.is_empty() {
            clauses.push(clause.to_string());
        }

        clauses
    }

    /// Normalizes intent by validating clause structure and extracting assumptions/exclusions.
    fn normalize_intent(
        clauses: &[String],
        assumptions: &mut Vec<String>,
        exclusions: &mut Vec<String>,
    ) -> Result<IntentNormalization, CompilationError> {
        // Check for modal/discretionary language
        for (i, clause) in clauses.iter().enumerate() {
            for modal_word in MODAL_WORDS {
                if contains_policy_term(clause, modal_word) {
                    return Err(CompilationError::ModalLanguageDetected {
                        clause_index: i,
                        clause: clause.clone(),
                        modal_word: modal_word.to_string(),
                    });
                }
            }
        }

        // Require at least one substantive action. Deontic auxiliaries such as
        // "must" and "shall" do not describe an enforceable action by themselves.
        for (i, clause) in clauses.iter().enumerate() {
            if action_positions(clause).is_empty() {
                return Err(CompilationError::MissingActionVerb {
                    clause_index: i,
                    clause: clause.clone(),
                });
            }
        }

        // Every consecutive pair of substantive actions must have an ordering
        // token between the two actions. An ordering word elsewhere in the
        // clause cannot make an unordered pair deterministic.
        for (i, clause) in clauses.iter().enumerate() {
            let tokens = normalized_tokens(clause);
            let positions = action_positions(clause);
            for pair in positions.windows(2) {
                let between = &tokens[pair[0] + 1..pair[1]];
                if !between
                    .iter()
                    .any(|token| ACTION_ORDERING_WORDS.contains(&token.as_str()))
                {
                    return Err(CompilationError::AmbiguousMultiAction {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                }
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
            if clause_lower.contains("except")
                || clause_lower.contains("exclude")
                || clause_lower.contains("unless")
            {
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
    fn compile_dio_invariants(
        clauses: &[String],
        dio_by_clause: &mut BTreeMap<usize, Vec<DIOInvariant>>,
    ) {
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
    fn compile_zt_authority(
        clauses: &[String],
        auth_by_clause: &mut BTreeMap<usize, Vec<ZTAuthority>>,
    ) -> Vec<CompilationError> {
        let mut errors = Vec::new();

        for (i, clause) in clauses.iter().enumerate() {
            match resolve_principal(clause) {
                PrincipalResolution::Unique(principal) => {
                    let authority_id = format!("zt_auth_{}", i);
                    let scope = clause.clone();

                    let delegation_rules = if ["delegate", "delegated", "delegation"]
                        .iter()
                        .any(|term| contains_policy_term(clause, term))
                    {
                        vec![clause.clone()]
                    } else {
                        Vec::new()
                    };
                    let revocation_triggers = if ["revoke", "revoked", "revocation"]
                        .iter()
                        .any(|term| contains_policy_term(clause, term))
                    {
                        vec![clause.clone()]
                    } else {
                        Vec::new()
                    };

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
                PrincipalResolution::Missing => {
                    errors.push(CompilationError::MissingPrincipal {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                }
                PrincipalResolution::Ambiguous => {
                    errors.push(CompilationError::AmbiguousPrincipal {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                }
            }
        }

        errors
    }

    /// Compiles ICAE cost constraints for clauses mentioning cost.
    fn compile_icae_constraints(
        clauses: &[String],
        cost_by_clause: &mut BTreeMap<usize, Vec<ICAECostConstraint>>,
    ) -> Vec<CompilationError> {
        let mut errors = Vec::new();

        for (i, clause) in clauses.iter().enumerate() {
            let has_cost_mention = COST_INDICATORS
                .iter()
                .any(|indicator| contains_policy_term(clause, indicator));

            if !has_cost_mention {
                continue;
            }

            // Rate windows cannot be represented truthfully by the current
            // public artifact. Fail closed before subject/unit extraction.
            if let Some(window) = extract_rate_window(clause) {
                errors.push(CompilationError::IntentNormalizationFailed {
                    reason: format!(
                        "Clause {} contains unsupported rate window '{}': '{}'",
                        i, window, clause
                    ),
                });
                continue;
            }

            let subject = match Self::extract_subject(clause) {
                Ok(Some(subject)) => subject,
                Ok(None) => {
                    errors.push(CompilationError::MissingCostSubject {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                    continue;
                }
                Err(()) => {
                    errors.push(CompilationError::AmbiguousCostSubject {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                    continue;
                }
            };

            let ceiling = match Self::extract_ceiling(clause) {
                Ok(value) => value,
                Err(value) => {
                    errors.push(CompilationError::InvalidCeiling {
                        clause_index: i,
                        clause: clause.clone(),
                        value,
                    });
                    continue;
                }
            };

            let measurement_units = measurement_units_from_clause(clause);
            let measurement_unit = match measurement_units.as_slice() {
                [unit] => *unit,
                [] => {
                    errors.push(CompilationError::MissingMeasurementUnit {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                    continue;
                }
                _ => {
                    errors.push(CompilationError::AmbiguousMeasurementUnit {
                        clause_index: i,
                        clause: clause.clone(),
                    });
                    continue;
                }
            };

            let constraint_id = format!("icae_{}", i);
            let externalities = if contains_policy_term(clause, "externality")
                || contains_policy_term(clause, "externalities")
                || contains_policy_term(clause, "external cost")
            {
                vec![clause.clone()]
            } else {
                Vec::new()
            };

            let constraint = ICAECostConstraint {
                id: constraint_id,
                subject,
                measurement_unit,
                clause_index: i,
                ceiling,
                externalities,
            };

            if let Some(list) = cost_by_clause.get_mut(&i) {
                list.push(constraint);
            }
        }

        errors
    }

    /// Extracts cost attribution subject from clause.
    fn extract_subject(clause: &str) -> Result<Option<String>, ()> {
        let tokens = normalized_tokens(clause);
        let spans = cost_indicator_spans(&tokens);
        let mut subjects = Vec::new();
        let mut indicators = Vec::new();

        for (start, end) in spans {
            let indicator = tokens[start..end].join(" ");
            if !indicators.contains(&indicator) {
                indicators.push(indicator);
            }

            let subject = if end < tokens.len() && (tokens[end] == "of" || tokens[end] == "for") {
                collect_subject_forward(&tokens, end + 1)
                    .or_else(|| collect_subject_backward(&tokens, start))
            } else {
                collect_subject_backward(&tokens, start)
            };
            if let Some(subject) = subject {
                if !subjects.contains(&subject) {
                    subjects.push(subject);
                }
            }
        }

        if indicators.len() > 1 || subjects.len() > 1 {
            Err(())
        } else {
            Ok(subjects.into_iter().next())
        }
    }

    /// Extracts an explicit upper bound. Positive `must exceed` language is a
    /// floor, not a ceiling, and is rejected rather than silently mistranslated.
    fn extract_ceiling(clause: &str) -> Result<Option<f64>, String> {
        let words: Vec<&str> = clause.split_whitespace().collect();
        // Match on each word's final alphanumeric segment so a compound such as
        // `rate-limit` is recognized exactly as the cost-indicator tokenizer
        // sees it, instead of compiling without the bound it states.
        let normalized_words: Vec<String> = words
            .iter()
            .map(|word| {
                word.rsplit(|character: char| !character.is_alphanumeric())
                    .find(|segment| !segment.is_empty())
                    .unwrap_or("")
                    .to_lowercase()
            })
            .collect();

        for (index, normalized) in normalized_words.iter().enumerate() {
            if normalized == "exceed" {
                let negative = normalized_words[index.saturating_sub(3)..index]
                    .iter()
                    .any(|word| word == "cannot" || word == "not");
                if !negative {
                    return Err("unsupported floor: exceed".to_string());
                }
                return Self::parse_ceiling_at(&words, &normalized_words, index + 1);
            }

            let relation_offset = match normalized.as_str() {
                "limit" | "limits" | "cap" | "caps" | "ceiling" | "ceilings" | "maximum"
                | "maximums" | "budget" | "budgets" | "quota" | "quotas" => Some(1),
                "limited" | "capped" => Some(1),
                _ => None,
            };
            if let Some(offset) = relation_offset {
                let relation_index = index + offset;
                let relation = normalized_words.get(relation_index).map(String::as_str);
                let value_index = if [Some("of"), Some("at"), Some("to")].contains(&relation) {
                    relation_index + 1
                } else {
                    relation_index
                };
                return Self::parse_ceiling_at(&words, &normalized_words, value_index);
            }
        }

        Ok(None)
    }

    /// Parses the ceiling literal at `value_index`. A literal that continues in
    /// the following word (`5 million`, `10 000`) is rejected, because its first
    /// word alone is a different number than the one written.
    fn parse_ceiling_at(
        words: &[&str],
        normalized_words: &[String],
        value_index: usize,
    ) -> Result<Option<f64>, String> {
        let ceiling = Self::parse_ceiling_value(words.get(value_index).copied())?;
        if let Some(next) = normalized_words.get(value_index + 1) {
            if next.starts_with(|character: char| character.is_ascii_digit())
                || ["hundred", "thousand", "million", "billion", "trillion"]
                    .contains(&next.as_str())
            {
                return Err(format!("{} {}", words[value_index], words[value_index + 1]));
            }
        }
        Ok(ceiling)
    }

    fn parse_ceiling_value(raw_value: Option<&str>) -> Result<Option<f64>, String> {
        let raw_value = raw_value.ok_or_else(|| "<missing>".to_string())?;
        // Strip surrounding punctuation only. Letters attached to the number
        // (`5k`, `2M`) scale it and must not be discarded.
        let literal = raw_value.trim_matches(|character: char| {
            !(character.is_alphanumeric()
                || character == '.'
                || character == '+'
                || character == '-')
        });
        let numeric_text =
            Self::strip_digit_group_separators(literal).ok_or_else(|| raw_value.to_string())?;

        let value = numeric_text
            .parse::<f64>()
            .map_err(|_| raw_value.to_string())?;
        if !value.is_finite() || value < 0.0 {
            return Err(raw_value.to_string());
        }
        Ok(Some(value))
    }

    /// Removes digit-group separators from a numeric literal. Returns `None`
    /// when a comma cannot be a group separator (for example the decimal comma
    /// in `0,5`), because dropping it would silently change the value.
    fn strip_digit_group_separators(literal: &str) -> Option<String> {
        if !literal.contains(',') {
            return Some(literal.to_string());
        }

        // Separators are only meaningful in the integer part of the mantissa.
        let integer_end = literal
            .find(|character: char| matches!(character, '.' | 'e' | 'E'))
            .unwrap_or(literal.len());
        let (integer, remainder) = literal.split_at(integer_end);
        if remainder.contains(',') {
            return None;
        }
        let digits = integer.trim_start_matches(|character: char| matches!(character, '+' | '-'));
        let sign = &integer[..integer.len() - digits.len()];

        let groups: Vec<&str> = digits.split(',').collect();
        let last = groups.len() - 1;
        for (index, group) in groups.iter().enumerate() {
            let valid_length = if index == 0 {
                (1..=3).contains(&group.len()) && !group.starts_with('0')
            } else if index == last {
                group.len() == 3
            } else {
                group.len() == 2 || group.len() == 3
            };
            if !valid_length || !group.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
        }

        Some(format!("{}{}{}", sign, groups.concat(), remainder))
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
        if clause.chars().count() <= max_len {
            clause.to_string()
        } else {
            let truncated: String = clause.chars().take(max_len).collect();
            format!("{}...", truncated)
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
            #[allow(deprecated)]
            failures,
        }
    }
}

fn resolve_principal(clause: &str) -> PrincipalResolution {
    let tokens = normalized_tokens(clause);
    let actions = action_positions(clause);
    let final_action = actions.last().copied();
    let mut explicit = Vec::new();

    for index in 0..tokens.len() {
        if tokens[index] != "by"
            || final_action
                .map(|action_index| index <= action_index)
                .unwrap_or(false)
        {
            continue;
        }

        let mut candidate_index = index + 1;
        if tokens.get(candidate_index).map(String::as_str) == Some("the") {
            candidate_index += 1;
        }
        if let Some(principal) = tokens
            .get(candidate_index)
            .and_then(|token| principal_token(token))
        {
            push_unique(&mut explicit, principal);
            candidate_index += 1;

            // Recognize coordinated principals following the same `by`, while
            // stopping before unrelated objects such as `for USER`.
            loop {
                match tokens.get(candidate_index).map(String::as_str) {
                    Some("and") | Some("or") => candidate_index += 1,
                    _ => {}
                }

                match tokens
                    .get(candidate_index)
                    .and_then(|token| principal_token(token))
                {
                    Some(principal) => {
                        push_unique(&mut explicit, principal);
                        candidate_index += 1;
                    }
                    None => break,
                }
            }
        }
    }

    // A clause-leading principal is active only when immediately followed by
    // a deontic auxiliary or substantive action. A noun phrase such as
    // `USER credentials` is an object mention, not an authority declaration.
    let leading = tokens.first().and_then(|token| principal_token(token));
    let active_leading = leading.filter(|_| {
        tokens.get(1).map(String::as_str).is_some_and(|token| {
            ["must", "shall", "cannot"].contains(&token) || ACTION_VERBS.contains(&token)
        })
    });
    if let Some(principal) = active_leading {
        push_unique(&mut explicit, principal);
    }

    match explicit.as_slice() {
        [principal] => PrincipalResolution::Unique(*principal),
        [] => PrincipalResolution::Missing,
        _ => PrincipalResolution::Ambiguous,
    }
}

fn principal_token(token: &str) -> Option<Principal> {
    match token {
        "system" => Some(Principal::System),
        "user" => Some(Principal::User),
        "service" => Some(Principal::Service),
        _ => None,
    }
}

fn push_unique<T: Copy + PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn measurement_units_from_clause(clause: &str) -> Vec<MeasurementUnit> {
    // Currency symbols are intentionally not accepted as explicit units.
    if ["$", "€", "£", "¥", "â‚¬", "Â£", "Â¥"]
        .iter()
        .any(|symbol| clause.contains(symbol))
    {
        return Vec::new();
    }

    let mut units = Vec::new();
    for token in normalized_tokens(clause) {
        let unit = match token.as_str() {
            "usd" => Some(MeasurementUnit::Usd),
            "eur" => Some(MeasurementUnit::Eur),
            "gbp" => Some(MeasurementUnit::Gbp),
            "tokens" => Some(MeasurementUnit::Tokens),
            "bytes" => Some(MeasurementUnit::Bytes),
            "requests" => Some(MeasurementUnit::Requests),
            "hours" => Some(MeasurementUnit::Hours),
            _ => None,
        };
        if let Some(unit) = unit {
            push_unique(&mut units, unit);
        }
    }
    units
}

fn action_positions(clause: &str) -> Vec<usize> {
    normalized_tokens(clause)
        .iter()
        .enumerate()
        .filter_map(|(index, token)| {
            if ACTION_VERBS.contains(&token.as_str())
                && !(index == 0 && is_past_participle_action(token))
            {
                Some(index)
            } else {
                None
            }
        })
        .collect()
}

fn is_past_participle_action(token: &str) -> bool {
    [
        "required",
        "logged",
        "audited",
        "recorded",
        "denied",
        "allowed",
        "enforced",
        "tracked",
        "delegated",
        "revoked",
        "approved",
        "limited",
        "capped",
    ]
    .contains(&token)
}

fn extract_rate_window(clause: &str) -> Option<String> {
    let tokens = normalized_tokens(clause);
    for token in &tokens {
        if [
            "monthly",
            "daily",
            "weekly",
            "yearly",
            "hourly",
            "annually",
            "quarterly",
        ]
        .contains(&token.as_str())
        {
            return Some(token.clone());
        }
    }
    for pair in tokens.windows(2) {
        if pair[0] == "per" {
            return Some(format!("per {}", pair[1]));
        }
        // `10 USD a month` and `10 USD/month` state the same rate window as
        // `10 USD every month`.
        if (["each", "every", "a", "an"].contains(&pair[0].as_str())
            || ["usd", "eur", "gbp", "tokens", "bytes", "requests", "hours"]
                .contains(&pair[0].as_str()))
            && [
                "hour", "hours", "day", "days", "week", "weeks", "month", "months", "year",
                "years", "quarter", "quarters",
            ]
            .contains(&pair[1].as_str())
        {
            return Some(format!("{} {}", pair[0], pair[1]));
        }
    }
    None
}

fn cost_indicator_spans(tokens: &[String]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if index + 1 < tokens.len()
            && ((tokens[index] == "resource" && tokens[index + 1] == "consumption")
                || (tokens[index] == "external"
                    && ["cost", "costs"].contains(&tokens[index + 1].as_str()))
                || (["cost", "costs"].contains(&tokens[index].as_str())
                    && [
                        "limit", "limits", "cap", "caps", "ceiling", "ceilings", "maximum",
                        "maximums",
                    ]
                    .contains(&tokens[index + 1].as_str())))
        {
            spans.push((index, index + 2));
            index += 2;
            continue;
        }

        if [
            "cost",
            "costs",
            "spend",
            "spends",
            "usage",
            "usages",
            "quota",
            "quotas",
            "externality",
            "externalities",
            "budget",
            "budgets",
            "expense",
            "expenses",
            "fee",
            "fees",
            "price",
            "prices",
            "charge",
            "charges",
            "limit",
            "limits",
            "cap",
            "caps",
            "ceiling",
            "ceilings",
            "maximum",
            "maximums",
        ]
        .contains(&tokens[index].as_str())
        {
            spans.push((index, index + 1));
        }
        index += 1;
    }
    spans
}

fn collect_subject_forward(tokens: &[String], start: usize) -> Option<String> {
    let mut subject = Vec::new();
    for token in tokens.iter().skip(start) {
        if is_skippable_subject_modifier(token) {
            continue;
        }
        if !is_valid_cost_subject(token) {
            break;
        }
        subject.push(token.clone());
    }
    if subject.is_empty() {
        None
    } else {
        Some(subject.join(" "))
    }
}

fn collect_subject_backward(tokens: &[String], end: usize) -> Option<String> {
    let mut subject = Vec::new();
    let mut index = end;
    while index > 0 {
        index -= 1;
        let token = &tokens[index];
        if is_skippable_subject_modifier(token) {
            continue;
        }
        if !is_valid_cost_subject(token) {
            break;
        }
        subject.push(token.clone());
    }
    subject.reverse();
    if subject.is_empty() {
        None
    } else {
        Some(subject.join(" "))
    }
}

fn is_skippable_subject_modifier(token: &str) -> bool {
    ["the", "a", "an", "each", "every"].contains(&token)
}

fn is_valid_cost_subject(token: &str) -> bool {
    if !token.chars().any(|character| character.is_alphabetic()) {
        return false;
    }
    if ACTION_VERBS.contains(&token) {
        return false;
    }

    ![
        "cost",
        "costs",
        "spend",
        "spends",
        "usage",
        "usages",
        "quota",
        "quotas",
        "resource",
        "consumption",
        "external",
        "externality",
        "externalities",
        "budget",
        "budgets",
        "expense",
        "expenses",
        "fee",
        "fees",
        "price",
        "prices",
        "charge",
        "charges",
        "limit",
        "limits",
        "cap",
        "caps",
        "ceiling",
        "ceilings",
        "maximum",
        "maximums",
        "the",
        "a",
        "an",
        "of",
        "for",
        "per",
        "in",
        "to",
        "from",
        "by",
        "all",
        "no",
        "not",
        "be",
        "must",
        "shall",
        "cannot",
        "then",
        "before",
        "after",
        "system",
        "user",
        "service",
        "usd",
        "eur",
        "gbp",
        "tokens",
        "bytes",
        "requests",
        "hours",
        "tracking",
        "auditing",
        "recording",
        "enforcing",
        "charging",
        "pricing",
        "monthly",
        "daily",
        "weekly",
        "yearly",
        "hourly",
        "annually",
        "quarterly",
    ]
    .contains(&token)
}

fn normalized_tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_lowercase())
        .collect()
}

fn contains_policy_term(text: &str, term: &str) -> bool {
    let tokens = normalized_tokens(text);
    let term_tokens = normalized_tokens(term);
    if term_tokens.is_empty() || term_tokens.len() > tokens.len() {
        return false;
    }

    tokens
        .windows(term_tokens.len())
        .any(|window| window == term_tokens.as_slice())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_principal_from_clause() {
        assert_eq!(Principal::from_clause("by SYSTEM"), Some(Principal::System));
        assert_eq!(Principal::from_clause("by USER"), Some(Principal::User));
        assert_eq!(
            Principal::from_clause("by SERVICE"),
            Some(Principal::Service)
        );
        assert_eq!(Principal::from_clause("by nobody"), None);
        // Word boundary test
        assert_eq!(Principal::from_clause("SYSTEMWIDE"), None);
    }

    #[test]
    fn test_measurement_unit_from_clause() {
        assert_eq!(
            MeasurementUnit::from_clause("1000 USD"),
            Some(MeasurementUnit::Usd)
        );
        assert_eq!(
            MeasurementUnit::from_clause("1000 tokens"),
            Some(MeasurementUnit::Tokens)
        );
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
