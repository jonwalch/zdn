use serde_json::Value;

// This deliberately small evaluator checks the documented policy intent. It is
// independent of the renderer and rejects unknown condition operators. It is
// not an AWS simulator: multi-resource checks/SCPs/resource policies are H1 gates.
pub(crate) fn strings(value: &Value) -> Vec<&str> {
    if let Some(s) = value.as_str() {
        vec![s]
    } else {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect()
    }
}
fn wildcard(pattern: &str, value: &str) -> bool {
    if let Some((head, tail)) = pattern.split_once('*') {
        value
            .strip_prefix(head)
            .is_some_and(|rest| (0..=rest.len()).any(|i| wildcard(tail, &rest[i..])))
    } else {
        pattern == value
    }
}
pub(crate) fn permitted(
    documents: &[Value],
    action: &str,
    resource: &str,
    context: &Value,
) -> bool {
    let mut allowed = false;
    for statement in documents
        .iter()
        .flat_map(|d| d["Statement"].as_array().unwrap())
    {
        let action_matches = match (statement.get("Action"), statement.get("NotAction")) {
            (Some(actions), None) => strings(actions).iter().any(|p| wildcard(p, action)),
            (None, Some(excluded)) => !strings(excluded).iter().any(|p| wildcard(p, action)),
            _ => panic!("policy must contain exactly one of Action and NotAction"),
        };
        if !action_matches
            || !strings(&statement["Resource"])
                .iter()
                .any(|p| wildcard(p, resource))
        {
            continue;
        }
        let conditions = statement.get("Condition").map(|v| v.as_object().unwrap());
        let matches = conditions.is_none_or(|c| {
            c.iter().all(|(operator, terms)| {
                terms.as_object().unwrap().iter().all(|(key, expected)| {
                    let expected = strings(expected);
                    let actual = context.get(key).map(strings).unwrap_or_default();
                    match operator.as_str() {
                        "Null" => {
                            expected
                                == [if context.get(key).is_none() {
                                    "true"
                                } else {
                                    "false"
                                }]
                        }
                        "StringEquals" | "ArnEquals" | "Bool" => {
                            actual.iter().any(|v| expected.contains(v))
                        }
                        "StringLike" => actual
                            .iter()
                            .any(|v| expected.iter().any(|p| wildcard(p, v))),
                        "StringNotEquals" | "ForAllValues:StringNotEquals" => {
                            actual.iter().all(|v| !expected.contains(v))
                        }
                        other => panic!("unsupported policy condition {other}"),
                    }
                })
            })
        });
        if matches {
            if statement["Effect"] == "Deny" {
                return false;
            }
            assert_eq!(statement["Effect"], "Allow");
            allowed = true;
        }
    }
    allowed
}
