-- TEMP-триггеры могут проверять связанные записи в подключённых базах.
-- Их необходимо устанавливать для каждого соединения DatabaseManager.

CREATE TEMP TRIGGER documents_owner_insert
BEFORE INSERT ON documents_store.documents
BEGIN
    SELECT RAISE(ABORT, 'Unknown document owner')
    WHERE NOT EXISTS (SELECT 1 FROM main.users WHERE id = NEW.owner_id);
END;
CREATE TEMP TRIGGER documents_owner_update
BEFORE UPDATE OF owner_id ON documents_store.documents
BEGIN
    SELECT RAISE(ABORT, 'Unknown document owner')
    WHERE NOT EXISTS (SELECT 1 FROM main.users WHERE id = NEW.owner_id);
END;

CREATE TEMP TRIGGER tables_links_insert
BEFORE INSERT ON tables_store.converted_tables
BEGIN
    SELECT RAISE(ABORT, 'Unknown table owner')
    WHERE NOT EXISTS (SELECT 1 FROM main.users WHERE id = NEW.owner_id);
    SELECT RAISE(ABORT, 'Unknown table direction')
    WHERE NOT EXISTS (SELECT 1 FROM main.directions WHERE id = NEW.direction_id);
    SELECT RAISE(ABORT, 'Unknown table secrecy level')
    WHERE NOT EXISTS (SELECT 1 FROM main.secrecy_levels WHERE id = NEW.secrecy_level_id);
    SELECT RAISE(ABORT, 'Unknown source document or revision')
    WHERE NEW.source_document_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM documents_store.documents
        WHERE id = NEW.source_document_id AND revision >= NEW.source_revision
    );
END;
CREATE TEMP TRIGGER tables_links_update
BEFORE UPDATE OF owner_id, direction_id, secrecy_level_id, source_document_id, source_revision
ON tables_store.converted_tables
BEGIN
    SELECT RAISE(ABORT, 'Unknown table owner')
    WHERE NOT EXISTS (SELECT 1 FROM main.users WHERE id = NEW.owner_id);
    SELECT RAISE(ABORT, 'Unknown table direction')
    WHERE NOT EXISTS (SELECT 1 FROM main.directions WHERE id = NEW.direction_id);
    SELECT RAISE(ABORT, 'Unknown table secrecy level')
    WHERE NOT EXISTS (SELECT 1 FROM main.secrecy_levels WHERE id = NEW.secrecy_level_id);
    SELECT RAISE(ABORT, 'Unknown source document or revision')
    WHERE NEW.source_document_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM documents_store.documents
        WHERE id = NEW.source_document_id AND revision >= NEW.source_revision
    );
END;

CREATE TEMP TRIGGER users_storage_delete
BEFORE DELETE ON main.users
BEGIN
    SELECT RAISE(ABORT, 'User owns stored documents or tables')
    WHERE EXISTS (SELECT 1 FROM documents_store.documents WHERE owner_id = OLD.id)
       OR EXISTS (SELECT 1 FROM tables_store.converted_tables WHERE owner_id = OLD.id);
END;
CREATE TEMP TRIGGER users_storage_id_update
BEFORE UPDATE OF id ON main.users WHEN NEW.id != OLD.id
BEGIN
    SELECT RAISE(ABORT, 'User owns stored documents or tables')
    WHERE EXISTS (SELECT 1 FROM documents_store.documents WHERE owner_id = OLD.id)
       OR EXISTS (SELECT 1 FROM tables_store.converted_tables WHERE owner_id = OLD.id);
END;
CREATE TEMP TRIGGER directions_storage_delete
BEFORE DELETE ON main.directions
BEGIN
    SELECT RAISE(ABORT, 'Direction is used by stored tables')
    WHERE EXISTS (SELECT 1 FROM tables_store.converted_tables WHERE direction_id = OLD.id);
END;
CREATE TEMP TRIGGER directions_storage_id_update
BEFORE UPDATE OF id ON main.directions WHEN NEW.id != OLD.id
BEGIN
    SELECT RAISE(ABORT, 'Direction is used by stored tables')
    WHERE EXISTS (SELECT 1 FROM tables_store.converted_tables WHERE direction_id = OLD.id);
END;
CREATE TEMP TRIGGER secrecy_storage_delete
BEFORE DELETE ON main.secrecy_levels
BEGIN
    SELECT RAISE(ABORT, 'Secrecy level is used by stored tables')
    WHERE EXISTS (SELECT 1 FROM tables_store.converted_tables WHERE secrecy_level_id = OLD.id);
END;
CREATE TEMP TRIGGER secrecy_storage_id_update
BEFORE UPDATE OF id ON main.secrecy_levels WHEN NEW.id != OLD.id
BEGIN
    SELECT RAISE(ABORT, 'Secrecy level is used by stored tables')
    WHERE EXISTS (SELECT 1 FROM tables_store.converted_tables WHERE secrecy_level_id = OLD.id);
END;

CREATE TEMP TRIGGER documents_source_delete
BEFORE DELETE ON documents_store.documents
BEGIN
    SELECT RAISE(ABORT, 'Document is used by stored tables')
    WHERE EXISTS (SELECT 1 FROM tables_store.converted_tables WHERE source_document_id = OLD.id);
END;
CREATE TEMP TRIGGER documents_source_id_update
BEFORE UPDATE OF id ON documents_store.documents WHEN NEW.id != OLD.id
BEGIN
    SELECT RAISE(ABORT, 'Document is used by stored tables')
    WHERE EXISTS (SELECT 1 FROM tables_store.converted_tables WHERE source_document_id = OLD.id);
END;
CREATE TEMP TRIGGER documents_source_revision_update
BEFORE UPDATE OF revision ON documents_store.documents
BEGIN
    SELECT RAISE(ABORT, 'Document revision is used by stored tables')
    WHERE EXISTS (
        SELECT 1 FROM tables_store.converted_tables
        WHERE source_document_id = OLD.id AND source_revision > NEW.revision
    );
END;
