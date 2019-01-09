@echo off

\masm32\bin\ml /c /coff HashCrypt.asm
\masm32\bin\Link /dll /subsystem:windows /libpath:\masm32\lib /def:HashCrypt.def HashCrypt.obj
