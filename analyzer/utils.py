from pathlib import Path


class FileUtils:

    @staticmethod
    def read_token(file_path: str) -> str:
        return Path(file_path).read_text(encoding="utf-8").strip()

    @staticmethod
    def read_key(file_path: str) -> str:
        return Path(file_path).read_text(encoding="utf-8")