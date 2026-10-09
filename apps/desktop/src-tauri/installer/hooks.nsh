; NetTrace installer hooks (included by Tauri's NSIS template).
; Saved as UTF-8 with BOM so NSIS reads the Russian text correctly.

; Live capture needs the Npcap driver, which may not be redistributed with the
; free license: after an interactive install, offer to open its download page.
; Silent, passive and update installs never prompt.
!macro NSIS_HOOK_POSTINSTALL
  ${IfNot} ${Silent}
  ${AndIf} $PassiveMode <> 1
  ${AndIf} $UpdateMode <> 1
    ; The installer is 32-bit: Sysnative is the real System32 on 64-bit Windows.
    ${IfNot} ${FileExists} "$WINDIR\Sysnative\Npcap\wpcap.dll"
    ${AndIfNot} ${FileExists} "$WINDIR\System32\Npcap\wpcap.dll"
    ; WinPcap-compatible Npcap installs into System32 itself (the app accepts both).
    ${AndIfNot} ${FileExists} "$WINDIR\Sysnative\wpcap.dll"
    ${AndIfNot} ${FileExists} "$WINDIR\System32\wpcap.dll"
      ${If} $LANGUAGE == 1049
        MessageBox MB_YESNO|MB_ICONINFORMATION "Для захвата трафика в реальном времени нужен бесплатный драйвер Npcap.$\r$\n$\r$\nБез него NetTrace открывает и анализирует файлы PCAP/PCAPNG.$\r$\n$\r$\nОткрыть страницу загрузки Npcap (npcap.com)?" /SD IDNO IDNO npcap_done
      ${Else}
        MessageBox MB_YESNO|MB_ICONINFORMATION "Live capture requires the free Npcap driver.$\r$\n$\r$\nWithout it NetTrace still opens and analyzes PCAP/PCAPNG files.$\r$\n$\r$\nOpen the Npcap download page (npcap.com)?" /SD IDNO IDNO npcap_done
      ${EndIf}
      ExecShell "open" "https://npcap.com/#download"
      npcap_done:
    ${EndIf}
  ${EndIf}
!macroend
