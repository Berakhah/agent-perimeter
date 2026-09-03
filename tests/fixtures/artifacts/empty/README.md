# Empty artifact fixture

Deliberately empty of any manifest (pyproject.toml, requirements.txt,
package.json) or source file (.py/.js/.ts). Stands in for a package with no
SDK pin and no parseable source - the unresolvable case detect.py must report
as UNKNOWN, not as "does not support".

This file exists only so git tracks the directory; it is not a source file
and carries none of detect.py's source signals.
