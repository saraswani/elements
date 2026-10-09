import re
from typing import List, Set, Tuple, Callable

# Operator precedence definitions
PRECEDENCE = {
    'NOT': 3,
    'AND': 2,
    'OR': 1
}

def lex_query(query_str: str) -> List[str]:
    """
    Tokenizes boolean search query string into keywords, operators, and parentheses.
    Example: "invoice AND (tax OR gst) NOT draft"
    -> ['invoice', 'AND', '(', 'tax', 'OR', 'gst', ')', 'NOT', 'draft']
    """
    pattern = r'\(|\)|AND|OR|NOT|"[^"]+"|[^\s()]+'
    raw_tokens = re.findall(pattern, query_str, re.IGNORECASE)
    tokens = []
    
    for token in raw_tokens:
        upper = token.upper()
        if upper in ('AND', 'OR', 'NOT', '(', ')'):
            tokens.append(upper)
        else:
            # Strip quotes if phrase
            clean_token = token.strip('"')
            if clean_token:
                tokens.append(clean_token)

    # Insert explicit AND for adjacent terms/parentheses (e.g. "invoice (tax OR gst)" -> "invoice AND (tax OR gst)")
    processed = []
    for i, token in enumerate(tokens):
        processed.append(token)
        if i < len(tokens) - 1:
            next_token = tokens[i+1]
            if (token not in ('AND', 'OR', 'NOT', '(') and 
                next_token not in ('AND', 'OR', 'NOT', ')')):
                processed.append('AND')
            elif token == ')' and next_token not in ('AND', 'OR', 'NOT', ')'):
                processed.append('AND')
            elif token not in ('AND', 'OR', 'NOT', '(') and next_token == '(':
                processed.append('AND')
                
    return processed


def to_rpn(tokens: List[str]) -> List[dict]:
    """
    Converts infix tokens to Reverse Polish Notation (RPN) using Dijkstra's Shunting-Yard algorithm.
    Distinguishes unary NOT vs binary NOT.
    """
    output_queue = []
    operator_stack = []

    for i, token in enumerate(tokens):
        if token in ('AND', 'OR'):
            while (operator_stack and operator_stack[-1] != '(' and
                   operator_stack[-1] in PRECEDENCE and
                   PRECEDENCE[operator_stack[-1]] >= PRECEDENCE[token]):
                output_queue.append({'type': 'op', 'val': operator_stack.pop()})
            operator_stack.append(token)
        elif token == 'NOT':
            # Check if NOT is unary or binary (e.g. "A NOT B" vs "NOT B")
            is_unary = (i == 0 or tokens[i-1] in ('AND', 'OR', 'NOT', '('))
            op_name = 'UNARY_NOT' if is_unary else 'NOT'
            
            while (operator_stack and operator_stack[-1] != '(' and
                   operator_stack[-1] in PRECEDENCE and
                   PRECEDENCE.get(operator_stack[-1], 0) >= PRECEDENCE['NOT']):
                output_queue.append({'type': 'op', 'val': operator_stack.pop()})
            operator_stack.append(op_name)
        elif token == '(':
            operator_stack.append('(')
        elif token == ')':
            while operator_stack and operator_stack[-1] != '(':
                output_queue.append({'type': 'op', 'val': operator_stack.pop()})
            if operator_stack and operator_stack[-1] == '(':
                operator_stack.pop()
        else:
            output_queue.append({'type': 'keyword', 'val': token})

    while operator_stack:
        op = operator_stack.pop()
        if op not in ('(', ')'):
            output_queue.append({'type': 'op', 'val': op})

    return output_queue


def evaluate_boolean_query(
    query_str: str,
    fetch_keyword_docs: Callable[[str], Tuple[Set[str], List[str]]],
    all_known_doc_ids: Set[str]
) -> Tuple[Set[str], List[str]]:
    """
    Parses and evaluates a boolean query against the SSE index.
    
    Args:
        query_str: raw search query (e.g., "invoice AND (tax OR gst) NOT draft")
        fetch_keyword_docs: callback function returning (doc_ids_set, queried_labels_list) for a keyword
        all_known_doc_ids: set of all indexed doc IDs (used for UNARY NOT operations)
        
    Returns:
        (matching_doc_ids_set, total_queried_labels_list)
    """
    if not query_str.strip():
        return set(), []

    tokens = lex_query(query_str)
    if not tokens:
        return set(), []

    rpn_queue = to_rpn(tokens)
    stack: List[Set[str]] = []
    all_queried_labels: List[str] = []

    for item in rpn_queue:
        if item['type'] == 'keyword':
            doc_set, labels = fetch_keyword_docs(item['val'])
            stack.append(set(doc_set))
            all_queried_labels.extend(labels)

        elif item['type'] == 'op':
            op = item['val']

            if op == 'UNARY_NOT':
                if stack:
                    right = stack.pop()
                    stack.append(all_known_doc_ids - right)
                else:
                    stack.append(set(all_known_doc_ids))

            elif op in ('AND', 'OR', 'NOT'):
                if len(stack) < 2:
                    # Fallback for malformed operator placement
                    if len(stack) == 1 and op == 'NOT':
                        right = stack.pop()
                        stack.append(all_known_doc_ids - right)
                    continue

                right = stack.pop()
                left = stack.pop()

                if op == 'AND':
                    stack.append(left & right)
                elif op == 'OR':
                    stack.append(left | right)
                elif op == 'NOT':
                    # Binary NOT: A NOT B means A - B
                    stack.append(left - right)

    final_results = stack[0] if stack else set()
    return final_results, list(dict.fromkeys(all_queried_labels))
