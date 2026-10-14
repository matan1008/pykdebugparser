class UnknownEnumValue(int):
    """
    A raw value that its enum doesn't define (e.g. a combination of flags or a value added in a newer OS).
    It has `name` and `value` like an enum member, so it is formatted as the raw number instead of failing the parse.
    """

    @property
    def name(self) -> str:
        return str(int(self))

    @property
    def value(self) -> int:
        return int(self)


def parse_enum(enum_type, value):
    """
    Convert a raw value to an enum member, falling back to `UnknownEnumValue` for values the enum doesn't define.
    """
    try:
        return enum_type(value)
    except ValueError:
        return UnknownEnumValue(value)
