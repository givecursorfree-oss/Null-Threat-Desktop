use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Prevent console windows from flashing when spawning CLI tools (clamscan, yara, ffprobe, etc.).
pub fn configure_hidden_subprocess(cmd: &mut Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
}
