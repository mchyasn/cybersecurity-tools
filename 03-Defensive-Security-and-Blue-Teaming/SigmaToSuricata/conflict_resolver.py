def resolve_conflicts(rules):
    seen = set()
    final = []
    for rule in rules:
        if rule in seen:
            continue
        final.append(rule)
        seen.add(rule)
    return final
