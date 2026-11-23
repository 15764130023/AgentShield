import pytest
from agentshield.tools.calculator import calculate


def test_calculator_respects_operator_precedence():
    result = calculate("2 + 3 * 4")

    assert result == 14


def test_calculator_evaluates_another_expression():
    result = calculate("(10 - 2) / 4")

    assert result == 2


def test_calculator_supports_negative_numbers():
    result = calculate("-3.5 + 2")

    assert result == -1.5

def test_calculator_rejects_function_calls():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate('open("secret.txt")')

def test_calculator_rejects_division_by_zero():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate("1 / 0")

def test_calculator_rejects_modulo_by_zero():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate("1 % 0")

def test_calculator_rejects_expression_longer_than_200_characters():
    expression = "1" + " + 1" * 50

    assert len(expression) == 201

    with pytest.raises(ValueError, match="表达式不合规"):
        calculate(expression)

def test_calculator_accepts_expression_with_exactly_200_characters():
    expression = "1" + " " * 199

    assert len(expression) == 200
    assert calculate(expression) == 1

def test_calculator_rejects_non_string_input():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate(123)

def test_calculator_converts_syntax_error_to_safe_error():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate("1 +")

def test_calculator_rejects_operand_greater_than_1000():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate("1001 + 1")

def test_calculator_accepts_operands_at_limit():
    assert calculate("1000") == 1000
    assert calculate("-1000") == -1000

def test_calculator_rejects_result_greater_than_1000000():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate("1000 * 1000 + 1")

def test_calculator_accepts_result_at_limit():
    assert calculate("1000 * 1000") == 1_000_000


def test_calculator_rejects_intermediate_result_over_limit():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate("(1000 * 1000 + 1) - 1")

def test_calculator_rejects_scientific_notation():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate("1e2 + 1")


@pytest.mark.parametrize(
    "expression",
    [
        "1\t+2",
        "1\r+2",
        "1\n+2",
    ],
)
def test_calculator_rejects_control_whitespace(expression):
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate(expression)

def test_calculator_rejects_consecutive_operators():
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate("1 + -2")

def test_calculator_rounds_decimal_result_to_two_places():
    result = calculate("1 / 3")

    assert result == 0.33

def test_calculator_rejects_parenthesis_depth_over_10():
    expression = "(" * 11 + "1" + ")" * 11

    with pytest.raises(ValueError, match="表达式不合规"):
        calculate(expression)


def test_calculator_accepts_parenthesis_depth_at_limit():
    expression = "(" * 10 + "1" + ")" * 10

    assert calculate(expression) == 1


@pytest.mark.parametrize(
    "expression",
    [
        "a + 1",
        '"1" + "2"',
        "2 ** 10",
        "4 // 2",
        "1 & 1",
        "1 | 2",
        "1 ^ 2",
        "~1",
        "1 << 2",
        "4 >> 1",
        "(1).real",
        '__import__("os")',
    ],
    ids=[
        "variable",
        "string",
        "power",
        "floor-division",
        "bitwise-and",
        "bitwise-or",
        "bitwise-xor",
        "bitwise-invert",
        "left-shift",
        "right-shift",
        "attribute-access",
        "import-call",
    ],
)
def test_calculator_rejects_forbidden_constructs(expression):
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate(expression)


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "   ",
        "()",
    ],
    ids=[
        "empty",
        "spaces-only",
        "empty-parentheses",
    ],
)
def test_calculator_rejects_empty_expressions(expression):
    with pytest.raises(ValueError, match="表达式不合规"):
        calculate(expression)
