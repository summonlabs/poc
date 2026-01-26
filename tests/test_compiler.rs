use poc::{
    PolicyCompiler, CompilationStatus, CompilationError,
    Principal, MeasurementUnit,
};
use std::thread;

// =============================================================================
// Input Validation Tests
// =============================================================================


#[test]
fn test_empty_policy_fails() {
    let compiler = PolicyCompiler::new();
    let result = compiler.compile("");
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(!result.errors.is_empty());
    assert!(matches!(result.errors[0], CompilationError::EmptyInput));
}

#[test]
fn test_whitespace_only_policy_fails() {
    let compiler = PolicyCompiler::new();
    let result = compiler.compile("   \n\t  ");
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(result.errors[0], CompilationError::EmptyInput));
}

#[test]
fn test_no_valid_clauses_fails() {
    let compiler = PolicyCompiler::new();
    let result = compiler.compile("...");
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(result.errors[0], CompilationError::NoClauses));
}

// =============================================================================
// Modal Language Detection Tests
// =============================================================================

#[test]
fn test_modal_language_fails() {
    let compiler = PolicyCompiler::new();
    let policy = "All actions should be logged.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(
        &result.errors[0],
        CompilationError::ModalLanguageDetected { modal_word, .. } if modal_word == "should"
    ));
}

#[test]
fn test_modal_may_fails() {
    let compiler = PolicyCompiler::new();
    let result = compiler.compile("Actions may be logged by SYSTEM.");
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(
        &result.errors[0],
        CompilationError::ModalLanguageDetected { modal_word, .. } if modal_word == "may"
    ));
}

#[test]
fn test_modal_where_reasonable_fails() {
    let compiler = PolicyCompiler::new();
    let result = compiler.compile("Log actions where reasonable by SYSTEM.");
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(
        &result.errors[0],
        CompilationError::ModalLanguageDetected { modal_word, .. } if modal_word == "where reasonable"
    ));
}

// =============================================================================
// Action Verb Validation Tests
// =============================================================================

#[test]
fn test_clause_without_recognized_action_verb_fails() {
    let compiler = PolicyCompiler::new();
    // This clause has no recognized action verb from ACTION_VERBS list
    // Note: "secure" is not in the list, and there's no log/audit/record/etc.
    let policy = "The system is secure by SYSTEM.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(
        &result.errors[0],
        CompilationError::MissingActionVerb { .. }
    ));
}

// =============================================================================
// Multi-Action / Ambiguity Tests
// =============================================================================

#[test]
fn test_multiple_actions_without_ordering_fails() {
    let compiler = PolicyCompiler::new();
    let policy = "Log all actions and audit them.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(
        &result.errors[0],
        CompilationError::AmbiguousMultiAction { .. }
    ));
}

#[test]
fn test_ordered_actions_with_then_passes() {
    let compiler = PolicyCompiler::new();
    // "then" indicates explicit ordering - should pass
    let policy = "Log actions then audit them by SYSTEM.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
}

// =============================================================================
// Successful Compilation Tests
// =============================================================================

#[test]
fn test_single_clause_compiles() {
    let compiler = PolicyCompiler::new();
    let policy = "All actions must be logged by SYSTEM.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
    assert!(result.is_success());
    assert_eq!(result.intent_normalization.clauses.len(), 1);
    assert_eq!(result.dio_invariants.len(), 1);
    assert_eq!(result.zt_authority_graph.len(), 1);
    assert_eq!(result.icae_constraints.len(), 0);
    assert_eq!(result.traceability_map.len(), 1);
    
    // Verify DIO invariant structure
    let dio = &result.dio_invariants[0];
    assert_eq!(dio.id, "dio_0");
    assert_eq!(dio.clause_index, 0);
    assert!(dio.failure_signal.contains("VIOLATION"));
    
    // Verify ZT authority structure
    let auth = &result.zt_authority_graph[0];
    assert_eq!(auth.id, "zt_auth_0");
    assert_eq!(auth.principal, Principal::System);
    assert_eq!(auth.clause_index, 0);
}

#[test]
fn test_multiple_clauses_compiles() {
    let compiler = PolicyCompiler::new();
    let policy = "All actions must be logged by SYSTEM. No unauthorized access allowed by USER.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
    assert_eq!(result.intent_normalization.clauses.len(), 2);
    assert_eq!(result.dio_invariants.len(), 2);
    assert_eq!(result.zt_authority_graph.len(), 2);
    assert_eq!(result.traceability_map.len(), 2);
    
    // Verify principals are correctly extracted
    assert_eq!(result.zt_authority_graph[0].principal, Principal::System);
    assert_eq!(result.zt_authority_graph[1].principal, Principal::User);
}

// =============================================================================
// Assumptions and Exclusions Tests
// =============================================================================

#[test]
fn test_assumptions_and_exclusions_parsed() {
    let compiler = PolicyCompiler::new();
    let policy = "Assumes network must be secure by SYSTEM. All actions must be logged by SYSTEM. Except for testing must be allowed by USER.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
    assert_eq!(result.intent_normalization.assumptions.len(), 1);
    assert_eq!(result.intent_normalization.exclusions.len(), 1);
    assert!(result.intent_normalization.assumptions[0].contains("Assumes"));
    assert!(result.intent_normalization.exclusions[0].contains("Except"));
}

// =============================================================================
// Cost Constraint Tests
// =============================================================================

#[test]
fn test_cost_clause_compiles() {
    let compiler = PolicyCompiler::new();
    let policy = "All actions must be logged by SYSTEM. Cost of logging cannot exceed 1000 USD per month by SERVICE.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
    assert_eq!(result.icae_constraints.len(), 1);
    
    let cost = &result.icae_constraints[0];
    assert_eq!(cost.id, "icae_1");
    assert_eq!(cost.measurement_unit, MeasurementUnit::Usd);
    assert_eq!(cost.clause_index, 1);
}

#[test]
fn test_cost_with_tokens_unit() {
    let compiler = PolicyCompiler::new();
    let policy = "Token usage of 5000 tokens must be tracked by SERVICE.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
    assert_eq!(result.icae_constraints.len(), 1);
    assert_eq!(result.icae_constraints[0].measurement_unit, MeasurementUnit::Tokens);
}

#[test]
fn test_cost_without_subject_fails() {
    let compiler = PolicyCompiler::new();
    // All words are stop words or too short - no valid subject
    let policy = "Cost must be for the by SYSTEM.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(
        &result.errors[0],
        CompilationError::MissingCostSubject { .. }
    ));
}

// =============================================================================
// Principal Validation Tests
// =============================================================================

#[test]
fn test_missing_principal_fails() {
   let compiler = PolicyCompiler::new();
    let policy = "All actions must be logged.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(
        &result.errors[0],
        CompilationError::MissingPrincipal { clause_index: 0, .. }
    ));
}

// =============================================================================
// Cost Validation Tests
// =============================================================================

#[test]
fn test_cost_mention_without_explicit_unit_fails() {
    let compiler = PolicyCompiler::new();
    let policy = "All actions must be logged by SYSTEM. Cost of logging cannot exceed $1000 per month by SERVICE.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    assert!(matches!(
        &result.errors[0],
        CompilationError::MissingMeasurementUnit { clause_index: 1, .. }
    ));
}

#[test]
fn test_cost_mention_with_explicit_unit_passes() {
    let compiler = PolicyCompiler::new();
    let policy = "All actions must be logged by SYSTEM. Cost of logging cannot exceed 1000 USD per month by SERVICE.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
    assert_eq!(result.icae_constraints.len(), 1);
}

// =============================================================================
// Traceability Tests
// =============================================================================

#[test]
fn test_clause_exact_traceability() {
    let compiler = PolicyCompiler::new();
    let policy = "All actions must be logged by SYSTEM. No unauthorized access allowed by USER.";
    let result = compiler.compile(policy);

    assert_eq!(result.verdict, CompilationStatus::Pass);
    assert_eq!(result.traceability_map.len(), 2);
    
    // Verify clause IDs
    assert_eq!(result.traceability_map[0].clause_id, "clause_0");
    assert_eq!(result.traceability_map[1].clause_id, "clause_1");
    
    // Verify clause indices
    assert_eq!(result.traceability_map[0].clause_index, 0);
    assert_eq!(result.traceability_map[1].clause_index, 1);
    
    // Verify exact artifact mapping - no cross-contamination
    assert!(result.traceability_map[0].invariant_ids.contains(&"dio_0".to_string()));
    assert!(!result.traceability_map[0].invariant_ids.contains(&"dio_1".to_string()));
    assert!(result.traceability_map[1].invariant_ids.contains(&"dio_1".to_string()));
    assert!(!result.traceability_map[1].invariant_ids.contains(&"dio_0".to_string()));
    
    // Verify authority IDs use new format
    assert!(result.traceability_map[0].authority_ids.contains(&"zt_auth_0".to_string()));
    assert!(result.traceability_map[1].authority_ids.contains(&"zt_auth_1".to_string()));
}

#[test]
fn test_traceability_includes_clause_text() {
    let compiler = PolicyCompiler::new();
    let policy = "All actions must be logged by SYSTEM.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
    assert!(!result.traceability_map[0].clause_text.is_empty());
    assert!(result.traceability_map[0].clause_text.contains("logged"));
}

// =============================================================================
// Thread Safety Tests
// =============================================================================

#[test]
fn test_concurrent_compilation() {
    // PolicyCompiler is now stateless, so we can just clone it
    let compiler = PolicyCompiler::new();
    let mut handles = vec![];
    
    for i in 0..10 {
        let compiler_clone = compiler.clone();
        let handle = thread::spawn(move || {
            let policy = format!("Action {} must be logged by SYSTEM.", i);
            let result = compiler_clone.compile(&policy);
            assert_eq!(result.verdict, CompilationStatus::Pass);
            result
        });
        handles.push(handle);
    }
    
    for handle in handles {
        let result = handle.join().expect("Thread panicked");
        assert!(result.is_success());
    }
}

#[test]
fn test_compiler_clone_independence() {
    let compiler1 = PolicyCompiler::new();
    let compiler2 = compiler1.clone();
    
    let result1 = compiler1.compile("Action A must be logged by SYSTEM.");
    let result2 = compiler2.compile("Action B must be audited by USER.");
    
    // Both should succeed independently
    assert!(result1.is_success());
    assert!(result2.is_success());
    
    // Results should reflect their respective inputs
    assert!(result1.traceability_map[0].clause_text.contains("Action A"));
    assert!(result2.traceability_map[0].clause_text.contains("Action B"));
}

// =============================================================================
// Determinism Tests
// =============================================================================

#[test]
fn test_deterministic_output() {
    let compiler = PolicyCompiler::new();
    let policy = "All actions must be logged by SYSTEM. Cost tracking requires 100 USD budget by SERVICE.";
    
    let result1 = compiler.compile(policy);
    let result2 = compiler.compile(policy);
    
    // Identical inputs must produce identical outputs
    assert_eq!(result1.verdict, result2.verdict);
    assert_eq!(result1.dio_invariants.len(), result2.dio_invariants.len());
    assert_eq!(result1.zt_authority_graph.len(), result2.zt_authority_graph.len());
    assert_eq!(result1.icae_constraints.len(), result2.icae_constraints.len());
    
    for i in 0..result1.dio_invariants.len() {
        assert_eq!(result1.dio_invariants[i].id, result2.dio_invariants[i].id);
        assert_eq!(result1.dio_invariants[i].clause_index, result2.dio_invariants[i].clause_index);
    }
    
    for i in 0..result1.zt_authority_graph.len() {
        assert_eq!(result1.zt_authority_graph[i].id, result2.zt_authority_graph[i].id);
        assert_eq!(result1.zt_authority_graph[i].principal, result2.zt_authority_graph[i].principal);
    }
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_very_long_clause_truncation() {
    let compiler = PolicyCompiler::new();
    let long_text = "a".repeat(200);
    let policy = format!("All {} must be logged by SYSTEM.", long_text);
    let result = compiler.compile(&policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
    // Descriptions should be truncated, not cause overflow
    assert!(result.dio_invariants[0].description.len() < 200);
}

#[test]
fn test_all_principals() {
    let compiler = PolicyCompiler::new();
    let policy = "Action A must be logged by SYSTEM. Action B must be audited by USER. Action C must be recorded by SERVICE.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
    assert_eq!(result.zt_authority_graph.len(), 3);
    
    let principals: Vec<Principal> = result.zt_authority_graph.iter()
        .map(|a| a.principal)
        .collect();
    assert!(principals.contains(&Principal::System));
    assert!(principals.contains(&Principal::User));
    assert!(principals.contains(&Principal::Service));
}

#[test]
fn test_all_measurement_units() {
    let compiler = PolicyCompiler::new();
    
    let test_cases = vec![
        ("Cost must be tracked in USD by SYSTEM.", MeasurementUnit::Usd),
        ("Cost must be tracked in EUR by SYSTEM.", MeasurementUnit::Eur),
        ("Cost must be tracked in GBP by SYSTEM.", MeasurementUnit::Gbp),
        ("Usage must be tracked in tokens by SYSTEM.", MeasurementUnit::Tokens),
        ("Usage must be tracked in bytes by SYSTEM.", MeasurementUnit::Bytes),
        ("Usage must be tracked in requests by SYSTEM.", MeasurementUnit::Requests),
        ("Usage must be tracked in hours by SYSTEM.", MeasurementUnit::Hours),
    ];
    
    for (policy, expected_unit) in test_cases {
        let result = compiler.compile(policy);
        assert_eq!(result.verdict, CompilationStatus::Pass, "Failed for: {}", policy);
        assert_eq!(result.icae_constraints.len(), 1, "Failed for: {}", policy);
        assert_eq!(result.icae_constraints[0].measurement_unit, expected_unit, "Failed for: {}", policy);
    }
}

// =============================================================================
// Error Message Quality Tests
// =============================================================================

#[test]
fn test_error_messages_are_actionable() {
    let compiler = PolicyCompiler::new();
    let result = compiler.compile("Actions should be logged by SYSTEM.");
    
    assert_eq!(result.verdict, CompilationStatus::Fail);
    let messages = result.error_messages();
    assert!(!messages.is_empty());
    
    // Error message should include context
    let msg = &messages[0];
    assert!(msg.contains("modal language"), "Message should mention modal language");
    assert!(msg.contains("should"), "Message should include the problematic word");
}

#[test]
fn test_compilation_result_helper_methods() {
    let compiler = PolicyCompiler::new();
    
    let success = compiler.compile("Action must be logged by SYSTEM.");
    assert!(success.is_success());
    assert!(success.error_messages().is_empty());
    
    let failure = compiler.compile("");
    assert!(!failure.is_success());
    assert!(!failure.error_messages().is_empty());
}

// =============================================================================
// Unicode and Special Character Tests
// =============================================================================

#[test]
fn test_unicode_in_policy_text() {
    let compiler = PolicyCompiler::new();
    // Unicode should be handled gracefully
    let policy = "All data must be logged by SYSTEM.";
    let result = compiler.compile(policy);
    
    assert_eq!(result.verdict, CompilationStatus::Pass);
}

#[test]
fn test_currency_symbols_rejected() {
    let compiler = PolicyCompiler::new();
    
    let symbols = ["$", "€", "£", "¥"];
    for symbol in &symbols {
        let policy = format!("Cost must not exceed {}100 by SYSTEM.", symbol);
        let result = compiler.compile(&policy);
        
        assert_eq!(result.verdict, CompilationStatus::Fail, 
            "Symbol {} should be rejected", symbol);
    }
}

// =============================================================================
// Regression Tests
// =============================================================================

#[test]
fn test_allow_is_action_verb() {
    let compiler = PolicyCompiler::new();
    let policy = "Access must be allowed by USER.";
    let result = compiler.compile(policy);
    
    // "allow" is in ACTION_VERBS, so this should pass
    assert_eq!(result.verdict, CompilationStatus::Pass);
}

#[test]
fn test_deny_is_action_verb() {
    let compiler = PolicyCompiler::new();
    let policy = "Access must be denied by SYSTEM.";
    let result = compiler.compile(policy);
    
    // "deny" is in ACTION_VERBS
    assert_eq!(result.verdict, CompilationStatus::Pass);
}