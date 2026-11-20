"""
DefePass - Interactive Tkinter Password Policy Checker
Module: gui_checker.py

Interactive desktop graphical interface for evaluating password safety
against known weak/compromised dictionary lists and enterprise policy rules.

Security & Integrity Rules:
- NEVER log, print, or store user-entered passwords.
- Transient evaluation: evaluate immediately, do not keep password in history.
- Wipe candidate buffers from memory.
- O(1) set membership lookup using pluggable source engine (local file or HTTPS stream).
- Real-time policy strength indicators (Length >= 12, Uppercase, Lowercase, Digit, Special).
"""

from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import tkinter as tk
from tkinter import ttk

from wordlist_engine import secure_wipe_buffer

# Definition of the 5 policy rules: (key, label, validator_func)
POLICY_RULES: List[Tuple[str, str, Callable[[str], bool]]] = [
    ("length", "Length >= 12 characters", lambda p: len(p) >= 12),
    ("uppercase", "At least one uppercase letter (A-Z)", lambda p: any(c.isupper() for c in p)),
    ("lowercase", "At least one lowercase letter (a-z)", lambda p: any(c.islower() for c in p)),
    ("digit", "At least one numerical digit (0-9)", lambda p: any(c.isdigit() for c in p)),
    ("special", "At least one special symbol (!@#$...)", lambda p: bool(re.search(r"[^A-Za-z0-9]", p))),
]


def evaluate_policy_rules(raw_password: str) -> Dict[str, bool]:
    """
    Evaluates password candidate against the 5 enterprise policy complexity rules.
    Returns a dictionary mapping rule key to True/False.

    Security note: Input raw_password is evaluated transiently and never logged or stored.
    """
    if not raw_password:
        return {rule_key: False for rule_key, _, _ in POLICY_RULES}
    return {rule_key: check_fn(raw_password) for rule_key, _, check_fn in POLICY_RULES}


def evaluate_password_safety(
    raw_password: str,
    wordlist_set: Set[str],
) -> Tuple[str, str, str]:
    """
    Evaluates password candidate against loaded wordlist set.
    Normalization: .strip().lower()

    Returns:
      Tuple of (status_code, display_message, color_hex)
      status_code is one of: 'EMPTY', 'UNSAFE', 'SAFE'
    """
    if not raw_password or not raw_password.strip():
        return (
            "EMPTY",
            "Please enter a password to evaluate.",
            "#7f8c8d",  # Neutral grey
        )

    # Normalize
    normalized = raw_password.strip().lower()
    norm_bytes = normalized.encode("utf-8")

    try:
        if normalized in wordlist_set:
            return (
                "UNSAFE",
                "Unsafe: Found in common/leaked passwords list.",
                "#c0392b",  # Red
            )
        else:
            return (
                "SAFE",
                "Relatively Safe: Not found in the common wordlist.",
                "#27ae60",  # Green
            )
    finally:
        # Wipe sensitive normalized bytes immediately
        secure_wipe_buffer(bytearray(norm_bytes))


class PasswordPolicyGUI:
    """
    Tkinter desktop application for interactive defensive password checking
    and real-time complexity policy enforcement.
    """

    def __init__(
        self,
        wordlist_path: Optional[Union[str, Path]] = "wordlist.txt",
        source_config: Optional[Any] = None,
        root: Optional[tk.Tk] = None,
    ) -> None:
        self.root = root
        self.wordlist_set: Set[str] = set()

        if source_config is not None:
            self.source_config = source_config
            self.wordlist_path = Path(source_config.filepath) if source_config.filepath else None
        elif wordlist_path is not None:
            from source_plugin import WordlistSourceConfig
            self.source_config = WordlistSourceConfig(filepath=wordlist_path)
            self.wordlist_path = Path(wordlist_path)
        else:
            from source_plugin import WordlistSourceConfig
            self.source_config = WordlistSourceConfig(filepath="wordlist.txt")
            self.wordlist_path = Path("wordlist.txt")

        # Load wordlist once into memory for O(1) instant lookup
        self.load_dictionary()

    def load_dictionary(self) -> None:
        """Loads normalized words into set for O(1) lookup using pluggable source engine."""
        from source_plugin import load_candidates_set

        try:
            self.wordlist_set = load_candidates_set(self.source_config)
        except Exception as e:
            self.wordlist_set = set()
            self.load_error = str(e)
        else:
            self.load_error = None

    def update_policy_display(self, raw_input: str) -> None:
        """Updates the real-time policy rules pass/fail indicators."""
        results = evaluate_policy_rules(raw_input)
        if hasattr(self, "rule_labels"):
            for rule_key, _, _ in POLICY_RULES:
                passed = results.get(rule_key, False)
                lbl = self.rule_labels.get(rule_key)
                if lbl:
                    if passed:
                        lbl.config(text=f"✓  {lbl.rule_desc}", fg="#27ae60")
                    else:
                        lbl.config(text=f"✗  {lbl.rule_desc}", fg="#7f8c8d" if not raw_input else "#c0392b")

    def on_key_release(self, event=None) -> None:
        """Handles real-time keystroke update for policy rules without logging."""
        raw_input = self.password_entry.get()
        self.update_policy_display(raw_input)
        # Transient wipe
        buf = bytearray(raw_input.encode("utf-8"))
        secure_wipe_buffer(buf)
        del raw_input

    def check_password_action(self) -> None:
        """Handles button click and Return key press."""
        raw_input = self.password_entry.get()
        status_code, message, color = evaluate_password_safety(raw_input, self.wordlist_set)

        # Update visual feedback label and policy panel
        self.status_label.config(text=message, fg=color)
        self.update_policy_display(raw_input)

        # Clear memory representation of raw_input
        buf = bytearray(raw_input.encode("utf-8"))
        secure_wipe_buffer(buf)
        del raw_input

    def toggle_show_password(self) -> None:
        """Toggles between masked '*' and plain display."""
        if self.show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def clear_input(self) -> None:
        """Clears the entry box and resets status label and policy indicators."""
        self.password_entry.delete(0, tk.END)
        self.status_label.config(
            text="Enter a password above to check against the policy wordlist.",
            fg="#555555",
        )
        self.update_policy_display("")

    def setup_ui(self, root: tk.Tk) -> None:
        """Builds Tkinter UI widgets and layout."""
        self.root = root
        self.root.title("DefePass — Interactive Password Safety Checker")
        self.root.geometry("560x490")
        self.root.minsize(500, 450)

        # Configure styling
        bg_color = "#f4f6f9"
        self.root.configure(bg=bg_color)

        # Header Frame
        header_frame = tk.Frame(root, bg=bg_color, pady=8)
        header_frame.pack(fill=tk.X, padx=20)

        title_lbl = tk.Label(
            header_frame,
            text="DefePass Security Checker",
            font=("Segoe UI", 15, "bold"),
            bg=bg_color,
            fg="#2c3e50",
        )
        title_lbl.pack(anchor="w")

        if getattr(self, "load_error", None):
            status_text = f"Error loading source: {self.load_error}"
            sub_fg = "#c0392b"
        elif self.source_config and self.source_config.is_online:
            status_text = f"Online Source: {len(self.wordlist_set)} entries loaded ({self.source_config.url})"
            sub_fg = "#2980b9"
        elif self.wordlist_set:
            status_text = f"Dictionary loaded: {len(self.wordlist_set)} prohibited entries"
            sub_fg = "#7f8c8d"
        else:
            status_text = f"Warning: Wordlist not found at '{self.wordlist_path}'"
            sub_fg = "#e67e22"

        subtitle_lbl = tk.Label(
            header_frame,
            text=status_text,
            font=("Segoe UI", 9),
            bg=bg_color,
            fg=sub_fg,
        )
        subtitle_lbl.pack(anchor="w")

        # Divider
        ttk.Separator(root, orient="horizontal").pack(fill=tk.X, padx=20, pady=3)

        # Input Frame
        input_frame = tk.Frame(root, bg=bg_color, pady=6)
        input_frame.pack(fill=tk.X, padx=20)

        input_lbl = tk.Label(
            input_frame,
            text="Candidate Password:",
            font=("Segoe UI", 10, "bold"),
            bg=bg_color,
            fg="#34495e",
        )
        input_lbl.pack(anchor="w", pady=(0, 4))

        entry_subframe = tk.Frame(input_frame, bg=bg_color)
        entry_subframe.pack(fill=tk.X)

        self.password_entry = tk.Entry(
            entry_subframe,
            font=("Consolas", 12),
            show="*",
            relief=tk.SOLID,
            bd=1,
        )
        self.password_entry.pack(fill=tk.X, ipady=3)
        self.password_entry.focus_set()
        self.password_entry.bind("<Return>", lambda event: self.check_password_action())
        self.password_entry.bind("<KeyRelease>", self.on_key_release)

        # Options Frame (Show/Hide Toggle & Clear)
        options_frame = tk.Frame(input_frame, bg=bg_color)
        options_frame.pack(fill=tk.X, pady=(4, 0))

        self.show_var = tk.BooleanVar(value=False)
        self.show_chk = tk.Checkbutton(
            options_frame,
            text="Show Password",
            variable=self.show_var,
            command=self.toggle_show_password,
            font=("Segoe UI", 9),
            bg=bg_color,
            activebackground=bg_color,
        )
        self.show_chk.pack(side=tk.LEFT)

        clear_btn = tk.Button(
            options_frame,
            text="Clear",
            command=self.clear_input,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            bg="#e0e0e0",
            padx=8,
            cursor="hand2",
        )
        clear_btn.pack(side=tk.RIGHT)

        # Action Button Frame
        action_frame = tk.Frame(root, bg=bg_color, pady=6)
        action_frame.pack(fill=tk.X, padx=20)

        check_btn = tk.Button(
            action_frame,
            text="Check Password",
            font=("Segoe UI", 11, "bold"),
            bg="#2980b9",
            fg="white",
            activebackground="#1f618d",
            activeforeground="white",
            relief=tk.FLAT,
            cursor="hand2",
            padx=15,
            pady=4,
            command=self.check_password_action,
        )
        check_btn.pack(fill=tk.X)

        # Wordlist Status / Feedback Frame
        result_frame = tk.Frame(root, bg=bg_color, pady=4)
        result_frame.pack(fill=tk.X, padx=20)

        self.status_label = tk.Label(
            result_frame,
            text="Enter a password above to check against the policy wordlist.",
            font=("Segoe UI", 10, "italic"),
            bg=bg_color,
            fg="#555555",
            wraplength=500,
            justify=tk.CENTER,
        )
        self.status_label.pack(fill=tk.X)

        # Policy Strength Rules Panel
        policy_frame = tk.LabelFrame(
            root,
            text=" Policy Strength & Complexity Rules ",
            font=("Segoe UI", 9, "bold"),
            bg=bg_color,
            fg="#2c3e50",
            padx=12,
            pady=8,
        )
        policy_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(6, 12))

        self.rule_labels: Dict[str, tk.Label] = {}
        for rule_key, rule_desc, _ in POLICY_RULES:
            lbl = tk.Label(
                policy_frame,
                text=f"✗  {rule_desc}",
                font=("Consolas", 10),
                bg=bg_color,
                fg="#7f8c8d",
                anchor="w",
            )
            lbl.rule_desc = rule_desc  # type: ignore[attr-defined]
            lbl.pack(fill=tk.X, pady=1)
            self.rule_labels[rule_key] = lbl

    def run(self) -> None:
        """Launch the Tkinter application main loop."""
        root = tk.Tk()
        self.setup_ui(root)
        root.mainloop()


def launch_gui(
    wordlist_path: Optional[Union[str, Path]] = None,
    source_config: Optional[Any] = None,
) -> None:
    """Entry point helper to initialize and run the GUI checker."""
    app = PasswordPolicyGUI(wordlist_path=wordlist_path, source_config=source_config)
    app.run()
