//! Colour themes shared by every TUI: the admin `manage` and `database` panels
//! and the replay player. Widgets take a [`Theme`] when they render rather than
//! keeping colours of their own, so switching it repaints everything at once.

use crate::config::ThemeName;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style, palette::tailwind};
use ratatui::widgets::{Clear, Widget};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub name: ThemeName,
    /// Panel background and body text.
    pub bg: Color,
    pub fg: Color,
    /// Every other table row.
    pub alt_bg: Color,
    /// Inactive tabs and secondary text.
    pub muted: Color,
    /// Borders of fields that do not have focus.
    pub border: Color,
    /// Focus: borders, the selected row, footers.
    pub accent: Color,
    /// The selected cell and the input cursor.
    pub accent_dim: Color,
    /// Text on a filled `accent`, `success`, `warning` or `error` badge.
    pub on_accent: Color,
    /// The active tab and table headers, with `bar_fg` on top.
    pub bar_bg: Color,
    pub bar_fg: Color,
    /// Titles of focused fields and popups.
    pub title: Color,
    /// The border of the field being edited.
    pub editing: Color,
    /// `accent`, `accent_dim` and `bar_bg` while a popup is on top.
    pub inactive: Color,
    pub inactive_dim: Color,
    pub inactive_bar: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
}

const fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

/// The terminal's own background and text, with blue accents. The background
/// can be light or dark, so there are no striped rows and every other colour
/// is a mid tone that reads on either.
pub const DEFAULT: Theme = Theme {
    name: ThemeName::Default,
    bg: Color::Reset,
    fg: Color::Reset,
    alt_bg: Color::Reset,
    muted: tailwind::SLATE.c500,
    border: tailwind::SLATE.c500,
    accent: tailwind::BLUE.c500,
    accent_dim: tailwind::BLUE.c600,
    on_accent: rgb(0xffffff),
    bar_bg: tailwind::BLUE.c700,
    bar_fg: tailwind::SLATE.c100,
    title: Color::Reset,
    editing: tailwind::SKY.c500,
    inactive: tailwind::GRAY.c500,
    inactive_dim: tailwind::GRAY.c600,
    inactive_bar: tailwind::GRAY.c600,
    success: tailwind::GREEN.c600,
    warning: tailwind::AMBER.c500,
    error: tailwind::RED.c500,
};

/// True black, for OLED screens: unlit background, few lit pixels elsewhere.
pub const OLED_BLACK: Theme = Theme {
    name: ThemeName::OledBlack,
    bg: rgb(0x000000),
    fg: tailwind::NEUTRAL.c200,
    alt_bg: rgb(0x0f0f0f),
    muted: tailwind::NEUTRAL.c500,
    border: tailwind::NEUTRAL.c700,
    accent: tailwind::SKY.c400,
    accent_dim: tailwind::SKY.c700,
    on_accent: rgb(0x000000),
    bar_bg: tailwind::NEUTRAL.c900,
    bar_fg: tailwind::SKY.c300,
    title: tailwind::NEUTRAL.c100,
    editing: tailwind::SKY.c300,
    inactive: tailwind::NEUTRAL.c500,
    inactive_dim: tailwind::NEUTRAL.c600,
    inactive_bar: tailwind::NEUTRAL.c900,
    success: tailwind::GREEN.c400,
    warning: tailwind::AMBER.c400,
    error: tailwind::RED.c500,
};

/// Pure white with dark text, for light terminals and bright rooms.
pub const OLED_WHITE: Theme = Theme {
    name: ThemeName::OledWhite,
    bg: rgb(0xffffff),
    fg: tailwind::NEUTRAL.c900,
    alt_bg: tailwind::NEUTRAL.c100,
    muted: tailwind::NEUTRAL.c500,
    border: tailwind::NEUTRAL.c300,
    accent: tailwind::BLUE.c600,
    accent_dim: tailwind::BLUE.c700,
    on_accent: rgb(0xffffff),
    bar_bg: tailwind::BLUE.c600,
    bar_fg: rgb(0xffffff),
    title: tailwind::NEUTRAL.c950,
    editing: tailwind::BLUE.c500,
    inactive: tailwind::NEUTRAL.c400,
    inactive_dim: tailwind::NEUTRAL.c500,
    inactive_bar: tailwind::NEUTRAL.c500,
    success: tailwind::GREEN.c600,
    warning: tailwind::AMBER.c600,
    error: tailwind::RED.c600,
};

/// <https://www.nordtheme.com/docs/colors-and-palettes>
pub const NORD: Theme = Theme {
    name: ThemeName::Nord,
    bg: rgb(0x2e3440),
    fg: rgb(0xd8dee9),
    alt_bg: rgb(0x3b4252),
    muted: rgb(0x7b88a1),
    border: rgb(0x4c566a),
    accent: rgb(0x88c0d0),
    accent_dim: rgb(0x5e81ac),
    on_accent: rgb(0x2e3440),
    bar_bg: rgb(0x434c5e),
    bar_fg: rgb(0xeceff4),
    title: rgb(0xeceff4),
    editing: rgb(0x8fbcbb),
    inactive: rgb(0x7b88a1),
    inactive_dim: rgb(0x616e88),
    inactive_bar: rgb(0x3b4252),
    success: rgb(0xa3be8c),
    warning: rgb(0xebcb8b),
    error: rgb(0xbf616a),
};

/// <https://github.com/morhetz/gruvbox>, dark.
pub const GRUVBOX: Theme = Theme {
    name: ThemeName::Gruvbox,
    bg: rgb(0x282828),
    fg: rgb(0xebdbb2),
    alt_bg: rgb(0x32302f),
    muted: rgb(0xa89984),
    border: rgb(0x504945),
    accent: rgb(0xfabd2f),
    accent_dim: rgb(0xd79921),
    on_accent: rgb(0x282828),
    bar_bg: rgb(0x504945),
    bar_fg: rgb(0xfbf1c7),
    title: rgb(0xfbf1c7),
    editing: rgb(0x8ec07c),
    inactive: rgb(0x928374),
    inactive_dim: rgb(0x7c6f64),
    inactive_bar: rgb(0x3c3836),
    success: rgb(0xb8bb26),
    warning: rgb(0xfe8019),
    error: rgb(0xfb4934),
};

impl Theme {
    pub const fn of(name: ThemeName) -> &'static Theme {
        match name {
            ThemeName::Default => &DEFAULT,
            ThemeName::OledBlack => &OLED_BLACK,
            ThemeName::OledWhite => &OLED_WHITE,
            ThemeName::Nord => &NORD,
            ThemeName::Gruvbox => &GRUVBOX,
        }
    }

    /// The theme after this one, wrapping around.
    pub fn next(&self) -> &'static Theme {
        let all = ThemeName::ALL;
        let i = all.iter().position(|n| *n == self.name).unwrap_or(0);
        Theme::of(all[(i + 1) % all.len()])
    }

    /// Body text on the panel background.
    pub const fn base(&self) -> Style {
        Style::new().fg(self.fg).bg(self.bg)
    }

    /// The background behind everything a frame draws. Without it a cell
    /// nothing paints keeps the terminal's own colours, which only `default`
    /// wants (its `bg` and `fg` are `Reset`).
    pub fn paint(&self, area: Rect, buf: &mut Buffer) {
        buf.set_style(area, self.base());
    }

    /// [`Clear`], then the theme's background: the ground a popup draws on.
    pub fn clear(&self, area: Rect, buf: &mut Buffer) {
        Clear.render(area, buf);
        self.paint(area, buf);
    }

    /// A scratch buffer for widgets drawn off-screen and copied in.
    pub fn buffer(&self, area: Rect) -> Buffer {
        let mut buf = Buffer::empty(area);
        self.paint(area, &mut buf);
        buf
    }

    /// Give cells left at the terminal's default colours the theme's instead.
    /// For a replayed session: its "default" means the theme, not whatever the
    /// viewer's terminal happens to use. A no-op for `default`, whose colours
    /// are the terminal's.
    pub fn fill_defaults(&self, buf: &mut Buffer) {
        for cell in buf.content.iter_mut() {
            if cell.fg == Color::Reset {
                cell.fg = self.fg;
            }
            if cell.bg == Color::Reset {
                cell.bg = self.bg;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_has_its_own_theme() {
        for name in ThemeName::ALL {
            assert_eq!(Theme::of(name).name, name);
        }
    }

    #[test]
    fn next_visits_every_theme_and_wraps() {
        let mut theme = Theme::of(ThemeName::Default);
        let mut seen = Vec::new();
        for _ in ThemeName::ALL {
            seen.push(theme.name);
            theme = theme.next();
        }
        assert_eq!(seen, ThemeName::ALL);
        assert_eq!(theme.name, ThemeName::Default);
    }

    #[test]
    fn oled_themes_use_pure_black_and_white() {
        assert_eq!(OLED_BLACK.bg, Color::Rgb(0, 0, 0));
        assert_eq!(OLED_WHITE.bg, Color::Rgb(255, 255, 255));
    }

    #[test]
    fn default_follows_the_terminal() {
        assert_eq!(
            DEFAULT.base(),
            Style::new().fg(Color::Reset).bg(Color::Reset)
        );
    }

    #[test]
    fn fill_defaults_keeps_explicit_colours() {
        let area = Rect::new(0, 0, 2, 1);
        let mut buf = Buffer::empty(area);
        buf[(1, 0)].set_fg(Color::Red);
        NORD.fill_defaults(&mut buf);
        assert_eq!(buf[(0, 0)].fg, NORD.fg);
        assert_eq!(buf[(0, 0)].bg, NORD.bg);
        assert_eq!(buf[(1, 0)].fg, Color::Red);
        assert_eq!(buf[(1, 0)].bg, NORD.bg);
    }
}
