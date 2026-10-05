# Adapted from detect-secrets' config transformer, with literal matching in
# place of per-option regex compilation. Copyright 2017-2018 Yelp Inc.
# Licensed under Apache-2.0; see _licenses/bc-detect-secrets.txt.
from __future__ import annotations

import configparser
from importlib.metadata import version

from detect_secrets.custom_types import NamedIO
from detect_secrets.transformers import config as native

_SUPPORTED_VERSION = version("bc-detect-secrets") == "1.5.50"
_NATIVE_FUNCTIONS = (
    native.ConfigFileTransformer.parse_file,
    native.EagerConfigFileTransformer.parse_file,
    native._parse_file,
    native.IniFileParser,
    native.IniFileParser.__init__,
    native.IniFileParser.__iter__,
    native.IniFileParser._get_value_and_line_offset,
    native._construct_values_list,
    native._is_allowlist_nextline_secret_comment,
)


def supported() -> bool:
    return (
        _SUPPORTED_VERSION
        and all(
            function.__module__ == "detect_secrets.transformers.config"
            for function in _NATIVE_FUNCTIONS
        )
        and (
            native.ConfigFileTransformer.parse_file,
            native.EagerConfigFileTransformer.parse_file,
            native._parse_file,
            native.IniFileParser,
            native.IniFileParser.__init__,
            native.IniFileParser.__iter__,
            native.IniFileParser._get_value_and_line_offset,
            native._construct_values_list,
            native._is_allowlist_nextline_secret_comment,
        )
        == _NATIVE_FUNCTIONS
    )


def _first_value_matches(line: str, key: str, value: str) -> bool:
    if not line.startswith(key):
        return False
    start = len(key)
    if start == len(line) or line[start] not in " :=":
        return False
    end = start + 1
    while end < len(line) and line[end] in " :=":
        end += 1
    if not value or value[0] not in " :=":
        return line.startswith(value, end)
    offset = line.find(value, start + 1)
    return offset != -1 and offset <= end


class _LiteralIniFileParser(native.IniFileParser):
    def __init__(self, file: NamedIO, add_header: bool = False) -> None:
        super().__init__(file, add_header=add_header)
        self._cursor = 0

    def _get_value_and_line_offset(self, key: str, values: str) -> list[tuple[str, int]]:
        parts = native._construct_values_list(values)
        if not parts:
            return []
        output: list[tuple[str, int]] = []
        part_index = 0
        for position in range(self._cursor, len(self.lines)):
            offset = position - self._cursor
            line = self.lines[position]
            if native._is_allowlist_nextline_secret_comment(line):
                output.append((line, self.line_offset + offset + 1))
            elif not line or self._comment_regex.match(line):
                continue
            elif part_index == 0:
                if _first_value_matches(line, key, parts[0]):
                    output.append((parts[0], self.line_offset + offset + 1))
                    part_index = 1
            elif part_index == len(parts):
                offset = max(offset, 1)
                self.line_offset += offset
                self._cursor += offset
                break
            else:
                output.append((parts[part_index], self.line_offset + offset + 1))
                part_index += 1
        else:
            self._cursor = len(self.lines)
        return output


class _ConfigLines(list[str]):
    def __init__(self, *, eager_equivalent: bool) -> None:
        super().__init__()
        self.eager_equivalent = eager_equivalent


def transform(file: NamedIO, *, add_header: bool = False) -> _ConfigLines | None:
    try:
        parser = _LiteralIniFileParser(file, add_header=add_header)
        lines = _ConfigLines(eager_equivalent=not add_header and not parser.parser.defaults())
        for key, value, number in parser:
            lines.extend([""] * max(number - 1 - len(lines), 0))
            if native._is_allowlist_nextline_secret_comment(value):
                lines.append(value)
                continue
            if value[0] in "\"'" and value[-1] == value[0]:
                value = value[1:-1]
            value = value.replace('"', '\\"')
            lines.append(f'{key} = "{value}"')
        return lines
    except configparser.Error:
        return None
    finally:
        file.seek(0)
