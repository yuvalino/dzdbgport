poetry publish -C python --build
poetry run -C python python -m build_exe
pushd vscode ; npm install && npm run compile && npx vsce package ; popd