import ast
from agentshield.models import RiskLevel, ToolSpec

_MAX_EXPRESSION_LENGTH = 200
_MAX_OPERAND_ABS = 1_000
_MAX_RESULT_ABS = 1_000_000
_MAX_PARENTHESIS_DEPTH = 10

_ALLOWED_CHARACTERS = "0123456789. ()+-*/%"
_OPERATORS = {"+", "-", "*", "/", "%"}
_SAFE_ERROR_MESSAGE = "表达式不合规"


def _validate_expression(expression: str) -> None:
    if type(expression) is not str:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if len(expression) > _MAX_EXPRESSION_LENGTH:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if any(character not in _ALLOWED_CHARACTERS for character in expression):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    previous_non_space = ""

    for character in expression:
        if character == " ":
            continue

        if character in _OPERATORS and previous_non_space in _OPERATORS:
            raise ValueError(_SAFE_ERROR_MESSAGE)

        previous_non_space = character

    parenthesis_depth = 0

    for character in expression:
        if character == "(":
            parenthesis_depth += 1

            if parenthesis_depth > _MAX_PARENTHESIS_DEPTH:
                raise ValueError(_SAFE_ERROR_MESSAGE)

        elif character == ")":
            parenthesis_depth -= 1

            if parenthesis_depth < 0:
                raise ValueError(_SAFE_ERROR_MESSAGE)

    if parenthesis_depth != 0:
        raise ValueError(_SAFE_ERROR_MESSAGE)


def _parse_expression(expression: str) -> ast.Expression:
    try:
        return ast.parse(expression, mode="eval")
    except SyntaxError:
        raise ValueError(_SAFE_ERROR_MESSAGE) from None


def calculate(expression: str) -> int | float:
    _validate_expression(expression)
    tree = _parse_expression(expression)
    result = _evaluate_node(tree.body)

    if type(result) is float:
        return round(result, 2)

    return result


def _evaluate_node(node: ast.AST) -> int | float:
    if isinstance(node, ast.Constant):
        if type(node.value) not in (int, float):
            raise ValueError(_SAFE_ERROR_MESSAGE)

        if abs(node.value) > _MAX_OPERAND_ABS:
            raise ValueError(_SAFE_ERROR_MESSAGE)

        return node.value

    if isinstance(node, ast.UnaryOp):
        operand = _evaluate_node(node.operand)

        if isinstance(node.op, ast.USub):
            return -operand

        if isinstance(node.op, ast.UAdd):
            return operand

        raise ValueError(_SAFE_ERROR_MESSAGE)

    if isinstance(node, ast.BinOp):
        left = _evaluate_node(node.left)
        right = _evaluate_node(node.right)

        if isinstance(node.op, ast.Add):
            result = left + right

        elif isinstance(node.op, ast.Sub):
            result = left - right

        elif isinstance(node.op, ast.Mult):
            result = left * right

        elif isinstance(node.op, ast.Div):
            if right == 0:
                raise ValueError(_SAFE_ERROR_MESSAGE)

            result = left / right

        elif isinstance(node.op, ast.Mod):
            if right == 0:
                raise ValueError(_SAFE_ERROR_MESSAGE)

            result = left % right

        else:
            raise ValueError(_SAFE_ERROR_MESSAGE)

        if abs(result) > _MAX_RESULT_ABS:
            raise ValueError(_SAFE_ERROR_MESSAGE)

        return result

    raise ValueError(_SAFE_ERROR_MESSAGE)


def _extract_expression(
    arguments: dict[str, object],
) -> str:
    if set(arguments) != {"expression"}:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    expression = arguments["expression"]

    if not isinstance(expression, str):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    return expression


def validate_calculator_arguments(
    arguments: dict[str, object],
) -> None:
    expression = _extract_expression(arguments)
    calculate(expression)


def handle_calculator(
    arguments: dict[str, object],
) -> object:
    expression = _extract_expression(arguments)
    return calculate(expression)


def create_calculator_spec() -> ToolSpec:
    return ToolSpec(
        name="calculator",
        description="执行受限的数学表达式计算",
        risk_level=RiskLevel.LOW,
        required_permissions={"calculator.use"},
        allowed_targets=set(),
        requires_confirmation=False,
        parameter_validator=validate_calculator_arguments,
        handler=handle_calculator,
    )
