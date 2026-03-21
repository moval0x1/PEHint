Optional: Microsoft Learn documentation (Markdown source)

PEHint reads import API hints only from local clones of Microsoft documentation (no bundled JSON).

1) Win32 API reference — MicrosoftDocs/sdk-api
   Clone: https://github.com/MicrosoftDocs/sdk-api
   Point PEHint at the "content" folder (nf-*.md per function):

     git clone --depth 1 https://github.com/MicrosoftDocs/sdk-api.git third_party/sdk-api

   The Markdown "content" folder is either:
     third_party/sdk-api/docs/sdk-api-src/content
   or
     third_party/sdk-api/sdk-api-src/content

   Environment variable (overrides auto-discovery):

     PEHINT_SDK_API_CONTENT=C:\...\third_party\sdk-api\sdk-api-src\content

2) Console APIs — MicrosoftDocs/Console-Docs (covers APIs not under sdk-api, e.g. WriteConsoleW)
   Clone: https://github.com/MicrosoftDocs/Console-Docs
   Point PEHint at the repository "docs" folder (e.g. writeconsole.md):

     git clone --depth 1 https://github.com/MicrosoftDocs/Console-Docs.git third_party/console-docs

     PEHINT_WINDOWS_CONSOLE_DOCS=C:\...\third_party\console-docs\docs

PEHint searches for sdk-api and Console-Docs by walking upward from the executable directory
and from the current working directory (see paths above).

What gets indexed
  - sdk-api: all nf-*.md files under "content"
  - Console-Docs: all *.md under "docs" (except index.md and nf-* filenames, if any)

Not every DLL import has a matching topic in these repos; if nothing matches, the Imports
panel shows a short "no summary" message with a footer link to search Microsoft Learn.

Documentation content is licensed under CC-BY-4.0; see the respective MicrosoftDocs repositories.
