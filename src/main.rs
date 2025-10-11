#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod collect_vec_sink;
mod directory_enumerator;
mod encryptor;
mod progress;

use crate::collect_vec_sink::CollectVecSink;
use crate::encryptor::{EncryptionMode, Encryptor};
use crate::progress::Progress;
use eframe::{
    egui::{self, CentralPanel},
    run_native,
    App,
};
use egui::{
    Button, Color32, ColorImage, Context, FontId, IconData, Image, InnerResponse, ProgressBar,
    RichText, TextStyle, TextureHandle, TextureOptions, TopBottomPanel, Ui, ViewportBuilder,
};
use spdlog::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs::File, io::Write};

struct VladsomwareApp {
    directory: PathBuf,
    key_path: String,
    key_saved_or_loaded: bool,
    encryptor: Encryptor,
    recursive: bool,
    verbose: bool,
    random_order: bool,
    encrypt_tex: TextureHandle,
    decrypt_tex: TextureHandle,

    log_sink: Arc<CollectVecSink>,
    current_mode: EncryptionMode,
    current_progress: Option<Arc<Progress>>,
}

fn icon_texture_from_icon_data(ctx: &Context, id: &str, icon: &IconData) -> TextureHandle {
    let color =
        ColorImage::from_rgba_unmultiplied([icon.width as usize, icon.height as usize], &icon.rgba);
    ctx.load_texture(id, color, TextureOptions::LINEAR)
}

impl VladsomwareApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let encrypt_icon = load_icon_safe(include_bytes!("../rsrc/lock.ico")).unwrap_or_default();
        let decrypt_icon = load_icon_safe(include_bytes!("../rsrc/unlock.ico")).unwrap_or_default();

        let vector_sink = Arc::new(CollectVecSink::new());
        let logger = Arc::new(Logger::builder().sink(vector_sink.clone()).build().unwrap());
        logger.set_level_filter(LevelFilter::MoreSevereEqual(Level::Info));
        spdlog::set_default_logger(logger.clone());

        info!("Vladsomware started");
        Self {
            directory: PathBuf::new(),
            key_path: String::new(),
            key_saved_or_loaded: false,
            encryptor: Encryptor::new().unwrap(),
            recursive: false,
            verbose: false,
            random_order: false,
            encrypt_tex: icon_texture_from_icon_data(
                &cc.egui_ctx,
                "encrypt_icon_tex",
                &encrypt_icon,
            ),
            decrypt_tex: icon_texture_from_icon_data(
                &cc.egui_ctx,
                "decrypt_icon_tex",
                &decrypt_icon,
            ),
            log_sink: vector_sink.clone(),
            current_mode: EncryptionMode::Encrypt,
            current_progress: None,
        }
    }
}
fn load_icon_safe(icon_bytes: &[u8]) -> Option<IconData> {
    let image = image::load_from_memory(icon_bytes).ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    let rgba = image.into_raw();

    Some(IconData {
        rgba,
        width,
        height,
    })
}

impl VladsomwareApp {
    fn set_style(&mut self, ctx: &Context) {
        let mut style = (*ctx.style()).clone();
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(24.0)),
            (TextStyle::Body, FontId::proportional(18.0)),
            (TextStyle::Monospace, FontId::monospace(18.0)),
            (TextStyle::Button, FontId::proportional(18.0)),
            (TextStyle::Small, FontId::proportional(14.0)),
        ]
        .into();
        ctx.set_style(style);

        if !ctx.style().visuals.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        }
    }

    fn render_dir_selector(&mut self, ui: &mut Ui, hover_text: &str) -> InnerResponse<()> {
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                ui.label("Directory to encrypt");
            });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                let mut path_str = self.directory.display().to_string();
                let text_edit_response = ui
                    .add(egui::TextEdit::singleline(&mut path_str).desired_width(250.0))
                    .on_hover_text(hover_text);

                if text_edit_response.changed() {
                    self.directory = PathBuf::from(path_str);
                }

                if ui.button("Browse...").on_hover_text(hover_text).clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        debug!("Set directory: {}", self.directory.display());
                        self.directory = path;
                    } else {
                        warn!("No directory selected");
                    }
                }
                ui.add_space(10.0);
            });
            ui.add_space(10.0);
        })
    }

    fn load_key(&mut self) -> Result<(), String> {
        let path = rfd::FileDialog::new()
            .set_title("Load Encryption Key")
            .add_filter("Key files", &["key", "bin"])
            .add_filter("All files", &["*"])
            .pick_file()
            .ok_or("No File Selected")?;

        self.encryptor
            .load_key(&path)
            .map_err(|e| format!("Failed to generate key: {}", e))?;
        self.key_saved_or_loaded = true;
        self.key_path = path.display().to_string();
        debug!("Loaded encryption key: {}", self.key_path);
        Ok(())
    }

    fn generate_and_save_key(&mut self) -> Result<(), String> {
        let path = rfd::FileDialog::new()
            .set_title("Save Encryption Key")
            .set_file_name("encryption_key.bin")
            .add_filter("Key files", &["key", "bin"])
            .add_filter("All files", &["*"])
            .save_file()
            .ok_or("No File Selected")?;

        self.key_path = path.display().to_string();

        self.encryptor
            .gen_key(
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_string(),
            )
            .map_err(|e| format!("Failed to generate key: {}", e))?;

        let mut file = File::create(&path).map_err(|e| format!("Failed to create file: {}", e))?;

        file.write_all(&self.encryptor.get_key_blob().unwrap())
            .map_err(|e| format!("Failed to write key: {}", e))?;

        self.key_saved_or_loaded = true;
        debug!("Saved encryption key: {}", self.key_path);
        Ok(())
    }

    fn render_encryption_key_handler(&mut self, ui: &mut Ui) -> InnerResponse<()> {
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                ui.label("Encryption Key");
            });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                if ui
                    .button("Load")
                    .on_hover_text("Load key to use for encryption\\decryption")
                    .clicked()
                {
                    self.load_key()
                        .map_err(|e| {
                            error!("{}", e);
                        })
                        .unwrap_or_default();
                };
                ui.add_space(10.0);
                ui.label("Or");
                ui.add_space(10.0);
                if ui
                    .button("Generate & Save")
                    .on_hover_text("Generate a key to use and save it")
                    .clicked()
                {
                    self.generate_and_save_key()
                        .map_err(|e| {
                            error!("{}", e);
                        })
                        .unwrap_or_default();
                }
            });
            ui.add_space(10.0);
        })
    }

    fn render_encryption_options(&mut self, ui: &mut Ui) -> InnerResponse<()> {
        ui.horizontal(|ui| {
            ui.add_space(10.0);
            ui.vertical(|ui| {
                ui.add_space(10.0);
                let mut rec_response = ui
                    .checkbox(&mut self.recursive, "Recursive")
                    .on_hover_text("Recursively Encrypt\\Decrypt all sub folders");
                if rec_response.changed() {
                    self.encryptor.set_recursive(self.recursive);
                    debug!("Recursive Encrypt: {}", self.recursive);
                }
                // @todo(vladi) implement multi threaded encryption.
                // ui.checkbox(&mut self.multi_threaded, "Multi-Threaded")
                //     .on_hover_text("Encrypt\\Decrypt using multiple threads");
                rec_response = ui
                    .checkbox(&mut self.verbose, "Verbose Logging")
                    .on_hover_text("Get Verbose logging information");
                if rec_response.changed() {
                    spdlog::default_logger().set_level_filter(if self.verbose {
                        LevelFilter::MoreSevereEqual(Level::Debug)
                    } else {
                        LevelFilter::MoreSevereEqual(Level::Info)
                    });
                    if self.verbose {
                        debug!("Verbose logging enabled");
                    }
                }

                rec_response = ui
                    .checkbox(&mut self.random_order, "Random order")
                    .on_hover_text("Encrypt files in a random order");
                if rec_response.changed() {
                    self.encryptor.set_random_order(self.random_order);
                    debug!("Random order: {}", self.random_order);
                }
                ui.add_space(10.0);
            });
        })
    }

    fn render_big_button(
        &mut self,
        ui: &mut Ui,
        button_text: &str,
        hover_text: &str,
        encryption: bool,
        button_color: impl Into<Color32>,
    ) -> InnerResponse<()> {
        let color: Color32 = button_color.into(); // copyable type
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            if ui
                .add_sized(
                    [340.0, 40.0],
                    Button::image_and_text(
                        Image::new(if encryption {
                            &self.encrypt_tex
                        } else {
                            &self.decrypt_tex
                        })
                        .max_width(25.0),
                        RichText::new(button_text).color(Color32::from_rgb(255, 255, 255)),
                    )
                    .fill(color),
                )
                .on_hover_text(hover_text)
                .clicked()
            {
                self.current_progress = Some(if encryption {
                    self.current_mode = EncryptionMode::Encrypt;
                    self.encryptor.encrypt_dir(&self.directory)
                } else {
                    self.current_mode = EncryptionMode::Decrypt;
                    self.encryptor.decrypt_dir(&self.directory)
                })
            };
            ui.add_space(20.0);
        })
    }

    fn render_encrypt_button(&mut self, ui: &mut Ui) -> InnerResponse<()> {
        self.render_big_button(
            ui,
            "Encrypt",
            "Encrypt the files in the directory",
            true,
            Color32::from_rgb(188, 40, 46),
        )
    }

    fn render_decrypt_button(&mut self, ui: &mut Ui) -> InnerResponse<()> {
        self.render_big_button(
            ui,
            "Decrypt",
            "Decrypt files in the directory",
            false,
            Color32::from_rgb(155, 176, 179),
        )
    }

    fn render_progress_bar(&mut self, ui: &mut Ui, ctx: &egui::Context) -> InnerResponse<()> {
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            let (frac, finished) = if let Some(p) = &self.current_progress {
                let s = p.snapshot();
                let frac = if s.total == 0 {
                    0.0
                } else if s.finished {
                    1.0
                } else {
                    (s.done as f32) / (s.total as f32)
                };
                (frac, s.finished)
            } else {
                (0.0, true) // default when nothing is running
            };
            let mut pb = ProgressBar::new(frac).show_percentage();
            if frac == 0.0 {
                pb = pb.fill(Color32::from_rgba_unmultiplied(0, 0, 0, 0));
            }
            ui.add_sized([340.0, 20.0], pb);

            if !finished {
                ctx.request_repaint_after(std::time::Duration::from_millis(33));
            }
        })
    }

    fn save_logs(&mut self) -> Result<(), String> {
        let path = rfd::FileDialog::new()
            .set_title("Save logs")
            .set_file_name("vladsomware.log")
            .add_filter("Log files", &["log"])
            .add_filter("All files", &["*"])
            .save_file()
            .ok_or("No file selected")?;

        let mut file = File::create(&path).map_err(|e| format!("{:?}", e))?;
        for log_context in &self.log_sink.collected() {
            writeln!(file, "{}", log_context.payload).map_err(|e| format!("{:?}", e))?;
        }

        Ok(())
    }

    fn level_color(level: Level) -> Color32 {
        match level {
            Level::Critical | Level::Error => Color32::from_rgb(188, 40, 46),
            Level::Warn => Color32::from_rgb(240, 200, 80),
            Level::Info | Level::Debug | Level::Trace => Color32::from_rgb(155, 176, 179),
        }
    }

    fn render_logs(&mut self, ui: &mut egui::Ui) -> InnerResponse<()> {
        ui.vertical(|ui| {
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                ui.label("Log:");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Save Logs").clicked() {
                        self.save_logs()
                            .map_err(|e| {
                                error!("Failed to save logs: {}", e);
                            })
                            .unwrap_or_default();
                    }
                })
            });
            ui.add_space(5.0);
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for log_context in &self.log_sink.collected() {
                        let styled_label = RichText::new(&log_context.payload)
                            .font(FontId::proportional(15.0))
                            .color(Self::level_color(log_context.level));
                        ui.label(styled_label);
                    }
                });
        })
    }
}

impl App for VladsomwareApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.set_style(ctx);
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                self.render_dir_selector(ui, "Path to directory to encrypt\\decrypt");
                ui.separator();
                self.render_encryption_key_handler(ui);
                ui.separator();
                self.render_encryption_options(ui);
                ui.separator();
                ui.vertical(|ui| {
                    ui.add_space(5.0);
                    self.render_encrypt_button(ui);
                    ui.add_space(5.0);
                    self.render_decrypt_button(ui);
                    ui.add_space(5.0);
                    self.render_progress_bar(ui, ctx);
                    ui.add_space(5.0);
                });
            });
        });

        TopBottomPanel::bottom("Logs")
            .exact_height(155.0)
            .show(ctx, |ui| {
                self.render_logs(ui);
            });
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut viewport_builder = ViewportBuilder::default()
        .with_inner_size([400.0, 560.0])
        .with_resizable(false);
    if let Some(icon) = load_icon_safe(include_bytes!("../rsrc/vladsomware.png")) {
        viewport_builder = viewport_builder.with_icon(icon);
    }
    let win_options = eframe::NativeOptions {
        viewport: viewport_builder,
        ..eframe::NativeOptions::default()
    };

    let _ = run_native(
        "Vladsomware",
        win_options,
        Box::new(|_ctx| Ok(Box::new(VladsomwareApp::new(_ctx)))),
    );

    Ok(())
}
