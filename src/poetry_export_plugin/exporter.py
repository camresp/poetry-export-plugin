import urllib.parse

from pathlib import Path
from typing import TYPE_CHECKING
from typing import List
from typing import Optional
from typing import Union


if TYPE_CHECKING:
    from cleo.io.io import IO
    from poetry.poetry import Poetry


class Exporter:
    """
    Exporter class to export a lock file to alternative formats.
    """

    FORMAT_REQUIREMENTS_TXT = "requirements.txt"
    FORMAT_GROUPS_JSON = 'grouped-requirements.json'
    #: The names of the supported export formats.
    ACCEPTED_FORMATS = (FORMAT_REQUIREMENTS_TXT, FORMAT_GROUPS_JSON)

    ALLOWED_HASH_ALGORITHMS = ("sha256", "sha384", "sha512")

    def __init__(self, poetry: "Poetry") -> None:
        self._poetry = poetry
        self._without_groups: Optional[List[str]] = None
        self._with_groups: Optional[List[str]] = None
        self._only_groups: Optional[List[str]] = None
        self._extras: Optional[List[str]] = None
        self._with_hashes: bool = True
        self._with_credentials: bool = False
        self._with_markers: bool = True

    def without_groups(self, groups: List[str]) -> "Exporter":
        self._without_groups = groups

        return self

    def with_groups(self, groups: List[str]) -> "Exporter":
        self._with_groups = groups

        return self

    def only_groups(self, groups: List[str]) -> "Exporter":
        self._only_groups = groups

        return self

    def with_extras(self, extras: List[str]) -> "Exporter":
        self._extras = extras

        return self

    def with_hashes(self, with_hashes: bool = True) -> "Exporter":
        self._with_hashes = with_hashes

        return self

    def with_credentials(self, with_credentials: bool = True) -> "Exporter":
        self._with_credentials = with_credentials

        return self

    def with_markers(self, with_markers: bool = True) -> 'Exporter':
        self._with_markers = with_markers

        return self

    def export(self, fmt: str, cwd: Path, output: Union["IO", str]) -> None:
        if fmt not in self.ACCEPTED_FORMATS:
            raise ValueError(f"Invalid export format: {fmt}")

        fmt_slug = fmt.replace(".", "_").replace('-', '_')
        getattr(self, f"_export_{fmt_slug}")(cwd, output)

    def _build_packages_for_export(self) -> List:
        from cleo.io.null_io import NullIO
        from poetry.core.packages.utils.utils import path_to_url
        from poetry.puzzle.solver import Solver
        from poetry.repositories.pool import Pool
        from poetry.repositories.repository import Repository


        if self._without_groups or self._with_groups or self._only_groups:
            if self._with_groups:
                # Default dependencies and opted-in optional dependencies
                root = self._poetry.package.with_dependency_groups(self._with_groups)
            elif self._without_groups:
                # Default dependencies without selected groups
                root = self._poetry.package.without_dependency_groups(
                    self._without_groups
                )
            else:
                # Only selected groups
                root = self._poetry.package.with_dependency_groups(
                    self._only_groups, only=True
                )
        else:
            root = self._poetry.package.with_dependency_groups(["default"], only=True)

        locked_repository = self._poetry.locker.locked_repository(True)

        pool = Pool(ignore_repository_names=True)
        pool.add_repository(locked_repository)

        solver = Solver(root, pool, Repository(), locked_repository, NullIO())
        # Everything is resolved at this point, so we no longer need
        # to load deferred dependencies (i.e. VCS, URL and path dependencies)
        solver.provider.load_deferred(False)

        ops = solver.solve().calculate_operations()
        packages = sorted([op.package for op in ops], key=lambda package: package.name)
        return root, packages

    def _export_grouped_requirements_json(self, cwd: Path, output: Union["IO", str]) -> None:
        import json

        dependency_items = []
        root, packages = self._build_packages_for_export()

        name_to_pkg = { p.name: p for p in packages }

        def walk_deps(dep):
            pkg = name_to_pkg[dep.name]
            yield pkg
            for subdep in pkg.all_requires:
                yield from walk_deps(subdep)

        pkgs_for_group = {}
        groups_for_pkg ={}
        for dep in root.all_requires:
            pkgs_in_groups = list(walk_deps(dep))
            for g in dep.groups:
                pkgs_for_group.setdefault(g, set()).update(p.name for p in pkgs_in_groups)

            for p in pkgs_in_groups:
                groups_for_pkg.setdefault(p.name, set()).update(dep.groups)


        dependency_packages = list(self._poetry.locker.get_project_dependency_packages(
            project_requires=root.all_requires,
            dev=True,
            extras=self._extras,
        ))

        for dependency_package in dependency_packages:

            entry = {}
            req_txt_line = ''
            dependency = dependency_package.dependency
            package = dependency_package.package

            if package not in packages:
                continue


            if package.develop:
                entry['develop'] = True

            requirement = dependency.to_pep_508(with_extras=False)
            is_direct_local_reference = (
                dependency.is_file() or dependency.is_directory()
            )
            is_direct_remote_reference = dependency.is_vcs() or dependency.is_url()

            if is_direct_remote_reference:
                req_txt_line = requirement
            elif is_direct_local_reference:
                dependency_uri = path_to_url(package.source_url)
                req_txt_line = f"{package.name} @ {dependency_uri}"
                entry['name'] = package.name
                entry['url'] = dependency_uri
            else:
                entry['name'] = package.name
                entry['version'] = str(package.version)
                req_txt_line = f"{package.name}=={package.version}"

            if not is_direct_remote_reference:
                if ";" in requirement:
                    markers = requirement.split(";", 1)[1].strip()
                    if markers and self._with_markers:
                        entry['markers'] = markers
                        req_txt_line += f"; {markers}"

            if (
                not is_direct_remote_reference
                and not is_direct_local_reference
                and package.source_url
            ):
                entry['source_url'] = package.source_url

            if package.files and self._with_hashes:
                hashes = []
                for f in package.files:
                    h = f["hash"]
                    algorithm = "sha256"
                    if ":" in h:
                        algorithm, h = h.split(":")

                        if algorithm not in self.ALLOWED_HASH_ALGORITHMS:
                            continue

                    hashes.append(f"{algorithm}:{h}")

                if hashes:
                    entry['hashes'] = list(hashes)
                    req_txt_line += " \\\n"
                    for i, h in enumerate(hashes):
                        req_txt_line += "    --hash={}{}".format(
                            h, " \\\n" if i < len(hashes) - 1 else ""
                        )

            entry['groups'] = list(groups_for_pkg[package.name])
            entry['req_entry'] = req_txt_line
            dependency_items.append(entry)

        self._output(json.dumps(dependency_items, indent=2), cwd, output)

    def _export_requirements_txt(self, cwd: Path, output: Union["IO", str]) -> None:

        indexes = set()
        content = ""
        dependency_lines = set()

        root, solved_packages = self._build_packages_for_export()

        for dependency_package in self._poetry.locker.get_project_dependency_packages(
            project_requires=root.all_requires,
            dev=True,
            extras=self._extras,
        ):
            line = ""

            dependency = dependency_package.dependency
            package = dependency_package.package

            if package not in solved_packages:
                continue

            if package.develop:
                line += "-e "

            requirement = dependency.to_pep_508(with_extras=False)
            is_direct_local_reference = (
                dependency.is_file() or dependency.is_directory()
            )
            is_direct_remote_reference = dependency.is_vcs() or dependency.is_url()

            if is_direct_remote_reference:
                line = requirement
            elif is_direct_local_reference:
                dependency_uri = path_to_url(package.source_url)
                line = f"{package.name} @ {dependency_uri}"
            else:
                line = f"{package.name}=={package.version}"

            if not is_direct_remote_reference:
                if ";" in requirement:
                    markers = requirement.split(";", 1)[1].strip()
                    if markers and self._with_markers:
                        line += f"; {markers}"

            if (
                not is_direct_remote_reference
                and not is_direct_local_reference
                and package.source_url
            ):
                indexes.add(package.source_url)

            if package.files and self._with_hashes:
                hashes = []
                for f in package.files:
                    h = f["hash"]
                    algorithm = "sha256"
                    if ":" in h:
                        algorithm, h = h.split(":")

                        if algorithm not in self.ALLOWED_HASH_ALGORITHMS:
                            continue

                    hashes.append(f"{algorithm}:{h}")

                if hashes:
                    line += " \\\n"
                    for i, h in enumerate(hashes):
                        line += "    --hash={}{}".format(
                            h, " \\\n" if i < len(hashes) - 1 else ""
                        )
            dependency_lines.add(line)

        content += "\n".join(sorted(dependency_lines))
        content += "\n"

        if indexes:
            # If we have extra indexes, we add them to the beginning of the output
            indexes_header = ""
            for index in sorted(indexes):
                repositories = [
                    r
                    for r in self._poetry.pool.repositories
                    if r.url == index.rstrip("/")
                ]
                if not repositories:
                    continue
                repository = repositories[0]
                if (
                    self._poetry.pool.has_default()
                    and repository is self._poetry.pool.repositories[0]
                ):
                    url = (
                        repository.authenticated_url
                        if self._with_credentials
                        else repository.url
                    )
                    indexes_header = f"--index-url {url}\n"
                    continue

                url = (
                    repository.authenticated_url
                    if self._with_credentials
                    else repository.url
                )
                parsed_url = urllib.parse.urlsplit(url)
                if parsed_url.scheme == "http":
                    indexes_header += f"--trusted-host {parsed_url.netloc}\n"
                indexes_header += f"--extra-index-url {url}\n"

            content = indexes_header + "\n" + content

        self._output(content, cwd, output)

    def _output(self, content: str, cwd: Path, output: Union["IO", str]) -> None:
        decoded = content
        try:
            output.write(decoded)
        except AttributeError:
            filepath = cwd / output
            with filepath.open("w", encoding="utf-8") as f:
                f.write(decoded)
