from __future__ import annotations

import urllib.parse

from typing import TYPE_CHECKING
from typing import Iterable

from cleo.io.io import IO
from poetry.repositories.http import HTTPRepository


try:
    from poetry.core.packages.dependency_group import MAIN_GROUP
except ImportError:
    MAIN_GROUP = "default"


if TYPE_CHECKING:
    from pathlib import Path

    from poetry.poetry import Poetry


class JSONExporter:
    """
    Exporter class to export a lock file to json formats.
    """

    FORMAT_JSON = 'grouped-requirements.json'

    ALLOWED_HASH_ALGORITHMS = ("sha256", "sha384", "sha512")

    EXPORT_METHODS = {
        FORMAT_JSON: "_export_grouped_requirements_json",
    }

    def __init__(self, poetry: Poetry) -> None:
        self._poetry = poetry
        self._with_hashes = True
        self._with_credentials = False
        self._with_urls = True
        self._without_groups = False
        self._with_groups = False
        self._with_markers = False
        self._extras: bool | list[str] | None = []
        self._groups: Iterable[str] = [MAIN_GROUP]

    @classmethod
    def is_format_supported(cls, fmt: str) -> bool:
        return fmt in cls.EXPORT_METHODS

    def with_extras(self, extras: bool | list[str] | None) -> Exporter:
        self._extras = extras

        return self

    def with_markers(self, with_markers: bool = True) -> Exporter:
        self._with_markers = with_markers

        return self

    def only_groups(self, groups: Iterable[str]) -> Exporter:
        self._groups = groups

        return self

    def with_urls(self, with_urls: bool = True) -> Exporter:
        self._with_urls = with_urls

        return self

    def with_hashes(self, with_hashes: bool = True) -> Exporter:
        self._with_hashes = with_hashes

        return self

    def with_credentials(self, with_credentials: bool = True) -> Exporter:
        self._with_credentials = with_credentials

        return self

    def export(self, fmt: str, cwd: Path, output: IO | str) -> None:
        if not self.is_format_supported(fmt):
            raise ValueError(f"Invalid export format: {fmt}")

        getattr(self, self.EXPORT_METHODS[fmt])(cwd, output)

    def _build_packages_for_export(self) -> List:
        from cleo.io.null_io import NullIO
        from poetry.core.packages.utils.utils import path_to_url
        from poetry.puzzle.solver import Solver
        from poetry.repositories.pool import Pool
        from poetry.repositories.repository import Repository


        if self._without_groups or self._with_groups or self._groups:
            if self._with_groups:
                # Default dependencies and opted-in optional dependencies
                root = self._poetry.package.with_dependency_groups(self._groups)
            elif self._without_groups:
                # Default dependencies without selected groups
                root = self._poetry.package.without_dependency_groups(
                    self._without_groups
                )
            else:
                # Only selected groups
                root = self._poetry.package.with_dependency_groups(
                    self._groups, only=True
                )
        else:
            root = self._poetry.package.with_dependency_groups(["default"], only=True)

        locked_repository = self._poetry.locker.locked_repository()

        pool = Pool(ignore_repository_names=True)
        pool.add_repository(locked_repository)

        solver = Solver(root, pool, Repository(), locked_repository, NullIO())
        # Everything is resolved at this point, so we no longer need
        # to load deferred dependencies (i.e. VCS, URL and path dependencies)
        solver.provider.load_deferred(False)

        ops = solver.solve().calculate_operations()
        packages = sorted([op.package for op in ops], key=lambda package: package.name)
        return root, packages

    def _export_grouped_requirements_json(self, cwd: Path, output: IO | str) -> None:

        import json

        dependency_items = []
        root, packages = self._build_packages_for_export()

        name_to_pkg = { p.name: p for p in packages }

        def walk_deps(dep):
            pkg = name_to_pkg[dep.name]
            yield pkg
            # breakpoint()
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


        dependency_packages = self._poetry.locker.get_project_dependency_packages(
            project_requires=root.all_requires,
            project_python_marker=root.python_marker,
            extras=self._extras,
        )
        # dependency_packages = list(self._poetry.locker.get_project_dependency_packages(
        #     project_requires=root.all_requires,
        #     dev=True,
        #     extras=self._extras,
        # ))

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

    def _export_requirements_txt(self, cwd: Path, output: IO | str) -> None:
        from poetry.core.packages.utils.utils import path_to_url

        indexes = set()
        content = ""
        dependency_lines = set()

        root = self._poetry.package.with_dependency_groups(
            list(self._groups), only=True
        )

        for dependency_package in self._poetry.locker.get_project_dependency_packages(
            project_requires=root.all_requires,
            project_python_marker=root.python_marker,
            extras=self._extras,
        ):
            line = ""

            dependency = dependency_package.dependency
            package = dependency_package.package

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
                assert dependency.source_url is not None
                dependency_uri = path_to_url(dependency.source_url)
                line = f"{package.complete_name} @ {dependency_uri}"
            else:
                line = f"{package.complete_name}=={package.version}"

            if not is_direct_remote_reference and ";" in requirement:
                markers = requirement.split(";", 1)[1].strip()
                if markers:
                    line += f" ; {markers}"

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

                hashes.sort()

                for h in hashes:
                    line += f" \\\n    --hash={h}"

            dependency_lines.add(line)

        content += "\n".join(sorted(dependency_lines))
        content += "\n"

        if indexes and self._with_urls:
            # If we have extra indexes, we add them to the beginning of the output
            indexes_header = ""
            for index in sorted(indexes):
                repositories = [
                    r
                    for r in self._poetry.pool.repositories
                    if isinstance(r, HTTPRepository) and r.url == index.rstrip("/")
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

    def _output(self, content: str, cwd: Path, output: IO | str) -> None:
        if isinstance(output, IO):
            output.write(content)
        else:
            filepath = cwd / output
            with filepath.open("w", encoding="utf-8") as f:
                f.write(content)
