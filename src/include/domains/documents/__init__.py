_EXPORTS = {
    "BaseObject": ".base",
    "EntityStatus": ".base",
    "Document": ".models",
    "DocumentRevision": ".models",
    "DocumentRevisionStatus": ".models",
    "DocumentAccessRule": ".models",
    "Folder": ".models",
    "FolderAccessRule": ".models",
    "DocumentMetadata": ".metadata",
    "DocumentMetadataTag": ".metadata",
    "File": ".files",
    "FileTask": ".files",
    "TransferMode": ".files",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(name)

    from importlib import import_module

    module = import_module(_EXPORTS[name], __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value
