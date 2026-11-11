import pathlib

from pydantic import BaseModel

from tests.utils.alembic_reader import ALEMBIC_MIGRATIONS, import_file


class AlembicMigration(BaseModel):
    path: pathlib.Path
    revision: str | None = None
    down_revision: str | tuple[str, ...] | None = None


def test_alembic_revisions_are_in_order() -> None:
    # read all files
    paths = sorted(ALEMBIC_MIGRATIONS.glob("*.py"))

    # convert to sorted list of AlembicMigration
    migrations: list[AlembicMigration] = []

    for path in paths:
        mod = import_file("alembic_version", path)

        revision = getattr(mod, "revision", None)
        down_revision = getattr(mod, "down_revision", None)

        migrations.append(
            AlembicMigration(
                path=path,
                revision=revision,
                down_revision=down_revision,
            )
        )

    seen: set[str] = set()
    heads: set[str] = set()
    for migration in migrations:
        assert migration.revision is not None, f"Missing revision in {migration.path}"
        assert migration.revision not in seen, f"Duplicate revision in {migration.path}"
        parents = migration.down_revision
        if isinstance(parents, str):
            parents = (parents,)
        if parents:
            assert set(parents) <= seen, f"Unknown or out-of-order parent in {migration.path}"
            heads.difference_update(parents)
        else:
            assert not seen, f"Multiple base revisions in {migration.path}"
        seen.add(migration.revision)
        heads.add(migration.revision)

    assert len(heads) == 1, f"Unmerged migration heads: {heads}"
