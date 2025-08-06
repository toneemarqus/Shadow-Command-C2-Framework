using System.Text;
using System.Text.RegularExpressions;

namespace C2Framework
{
    public class EnhancedFileItem
    {
        public string Name { get; set; }
        public bool IsDirectory { get; set; }
        public string Size { get; set; }
        public string FullPath { get; set; }
    }

    public partial class EnhancedFileExplorer : Form
    {
        private readonly ClientHandler _client;
        private readonly MainForm _mainForm;
        private readonly C2Server _server;
        private string _currentPath = "";
        private bool _isLinux;
        private bool _isNavigating = false;
        private ImageList fileIconImageList;

        // UI Controls
        private ListView lvFiles;
        private TextBox txtCurrentPath;
        private Button btnRefresh;
        private Button btnUp;
        private Button btnHome;
        private Button btnNewFolder;
        private StatusStrip statusStrip;
        private ToolStripStatusLabel statusLabel;
        private ToolStripProgressBar progressBar;
        private ContextMenuStrip contextMenuFiles;
        private Panel navigationPanel;
        private Panel toolbarPanel;

        // Context menu items
        private ToolStripMenuItem downloadMenuItem;
        private ToolStripMenuItem uploadMenuItem;
        private ToolStripMenuItem deleteMenuItem;
        private ToolStripMenuItem refreshMenuItem;
        private ToolStripMenuItem newFolderMenuItem;
        private ToolStripMenuItem copyPathMenuItem;
        private ToolStripMenuItem propertiesMenuItem;
        private ToolStripSeparator separator1;
        private ToolStripSeparator separator2;
        private ToolStripMenuItem permissionsMenuItem;
        private ToolStripMenuItem symlinkMenuItem;

        public EnhancedFileExplorer(ClientHandler client, MainForm mainForm, C2Server server)
        {
            if (client == null)
                throw new ArgumentNullException(nameof(client), "Client cannot be null");
            if (server == null)
                throw new ArgumentNullException(nameof(server), "Server cannot be null");

            _client = client;
            _mainForm = mainForm;
            _server = server;
            _isLinux = client.IsLinux;


            InitializeComponent();
            SetupUI();

            this.Text = $"File Explorer - BEACON {_client.ClientId} ({_client.UserName}@{_client.ComputerName})";

            InitializeFileExplorer();
        }

        private void InitializeComponent()
        {
            this.Size = new Size(1000, 700);
            this.StartPosition = FormStartPosition.CenterParent;
            this.Text = $"File Explorer - {_client.ClientId} ({_client.UserName}@{_client.ComputerName})";
            this.MinimumSize = new Size(800, 500);

            // Apply dark theme
            this.BackColor = Color.FromArgb(30, 30, 30);
            this.ForeColor = Color.FromArgb(220, 220, 220);
        }

        private void SetupUI()
        {
            // Create main layout
            CreateNavigationPanel();
            CreateToolbarPanel();
            CreateFileListView();
            CreateContextMenu();
            CreateStatusStrip();
            CreateFileIcons();

            lvFiles.ContextMenuStrip = contextMenuFiles;

            this.Controls.Add(lvFiles);
            this.Controls.Add(toolbarPanel);
            this.Controls.Add(navigationPanel);
            this.Controls.Add(statusStrip);
        }

        private void CreateFileIcons()
        {
            try
            {
                fileIconImageList = new ImageList();
                fileIconImageList.ImageSize = new Size(32, 32);
                fileIconImageList.ColorDepth = ColorDepth.Depth32Bit;

                CreateFileTypeIcons();

                // Assign to ListView
                lvFiles.LargeImageList = fileIconImageList;
                lvFiles.SmallImageList = fileIconImageList;
            }
            catch (Exception ex)
            {
            }
        }

        private void CreateFileTypeIcons()
        {
            // 0: Folder icon
            fileIconImageList.Images.Add("folder", CreateFolderIcon());

            // 1: Junction icon
            fileIconImageList.Images.Add("junction", CreateJunctionIcon());

            // 2: Text file icon
            fileIconImageList.Images.Add("text", CreateTextFileIcon());

            // 3: Executable icon
            fileIconImageList.Images.Add("exe", CreateExecutableIcon());

            // 4: Image icon
            fileIconImageList.Images.Add("image", CreateImageIcon());

            // 5: Archive icon
            fileIconImageList.Images.Add("archive", CreateArchiveIcon());

            // 6: Document icon
            fileIconImageList.Images.Add("document", CreateDocumentIcon());

            // 7: System file icon
            fileIconImageList.Images.Add("system", CreateSystemFileIcon());

            // 8: Script icon
            fileIconImageList.Images.Add("script", CreateScriptIcon());

            // 9: Default file icon
            fileIconImageList.Images.Add("default", CreateDefaultFileIcon());

            // 10: Up arrow for parent directory
            fileIconImageList.Images.Add("up", CreateUpArrowIcon());
        }

        private Bitmap CreateFolderIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Folder shape
                using (Brush folderBrush = new SolidBrush(Color.FromArgb(255, 205, 102)))
                {
                    // Main folder body
                    Rectangle folderRect = new Rectangle(4, 12, 24, 16);
                    g.FillRectangle(folderBrush, folderRect);

                    // Folder tab
                    Rectangle tabRect = new Rectangle(4, 8, 10, 4);
                    g.FillRectangle(folderBrush, tabRect);
                }

                // Folder outline
                using (Pen outlinePen = new Pen(Color.FromArgb(184, 134, 11), 1))
                {
                    g.DrawRectangle(outlinePen, 4, 12, 24, 16);
                    g.DrawRectangle(outlinePen, 4, 8, 10, 4);
                }
            }
            return bmp;
        }

        private Bitmap CreateJunctionIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Base folder (similar to folder icon but different colour)
                using (Brush folderBrush = new SolidBrush(Color.FromArgb(255, 165, 0)))
                {
                    Rectangle folderRect = new Rectangle(4, 12, 24, 16);
                    g.FillRectangle(folderBrush, folderRect);
                    Rectangle tabRect = new Rectangle(4, 8, 10, 4);
                    g.FillRectangle(folderBrush, tabRect);
                }

                // Link arrow
                using (Brush arrowBrush = new SolidBrush(Color.White))
                {
                    Point[] arrowPoints = {
                new Point(20, 18),
                new Point(24, 18),
                new Point(22, 16),
                new Point(22, 17),
                new Point(24, 17),
                new Point(24, 19),
                new Point(22, 19),
                new Point(22, 20)
            };
                    g.FillPolygon(arrowBrush, arrowPoints);
                }
            }
            return bmp;
        }

        private Bitmap CreateTextFileIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Document background
                using (Brush docBrush = new SolidBrush(Color.White))
                {
                    Rectangle docRect = new Rectangle(6, 4, 18, 24);
                    g.FillRectangle(docBrush, docRect);
                }

                // Document outline
                using (Pen outlinePen = new Pen(Color.Gray, 1))
                {
                    g.DrawRectangle(outlinePen, 6, 4, 18, 24);
                }

                // Text lines
                using (Pen textPen = new Pen(Color.FromArgb(64, 64, 64), 1))
                {
                    g.DrawLine(textPen, 8, 8, 20, 8);
                    g.DrawLine(textPen, 8, 11, 22, 11);
                    g.DrawLine(textPen, 8, 14, 18, 14);
                    g.DrawLine(textPen, 8, 17, 21, 17);
                }
            }
            return bmp;
        }

        private Bitmap CreateExecutableIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Executable background (gear-like)
                using (Brush exeBrush = new SolidBrush(Color.FromArgb(120, 120, 120)))
                {
                    Rectangle gearRect = new Rectangle(8, 8, 16, 16);
                    g.FillEllipse(exeBrush, gearRect);
                }

                // Centre circle
                using (Brush centerBrush = new SolidBrush(Color.FromArgb(80, 80, 80)))
                {
                    Rectangle centerRect = new Rectangle(12, 12, 8, 8);
                    g.FillEllipse(centerBrush, centerRect);
                }

                // Gear teeth
                using (Brush toothBrush = new SolidBrush(Color.FromArgb(140, 140, 140)))
                {
                    Rectangle[] teeth = {
                new Rectangle(15, 4, 2, 4),
                new Rectangle(24, 15, 4, 2),
                new Rectangle(15, 24, 2, 4),
                new Rectangle(4, 15, 4, 2)
            };
                    foreach (var tooth in teeth)
                        g.FillRectangle(toothBrush, tooth);
                }
            }
            return bmp;
        }

        private Bitmap CreateImageIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Image frame
                using (Brush frameBrush = new SolidBrush(Color.FromArgb(220, 220, 220)))
                {
                    Rectangle frameRect = new Rectangle(4, 6, 24, 20);
                    g.FillRectangle(frameBrush, frameRect);
                }

                // Frame border
                using (Pen borderPen = new Pen(Color.Gray, 1))
                {
                    g.DrawRectangle(borderPen, 4, 6, 24, 20);
                }

                // Mountain shape
                using (Brush mountainBrush = new SolidBrush(Color.FromArgb(100, 150, 100)))
                {
                    Point[] mountain = {
                new Point(6, 22),
                new Point(12, 14),
                new Point(18, 18),
                new Point(26, 10),
                new Point(26, 22)
            };
                    g.FillPolygon(mountainBrush, mountain);
                }

                // Sun
                using (Brush sunBrush = new SolidBrush(Color.FromArgb(255, 215, 0)))
                {
                    g.FillEllipse(sunBrush, 20, 8, 6, 6);
                }
            }
            return bmp;
        }

        private Bitmap CreateArchiveIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Archive box
                using (Brush boxBrush = new SolidBrush(Color.FromArgb(139, 69, 19)))
                {
                    Rectangle boxRect = new Rectangle(6, 8, 20, 18);
                    g.FillRectangle(boxBrush, boxRect);
                }

                // Box outline
                using (Pen outlinePen = new Pen(Color.FromArgb(101, 67, 33), 1))
                {
                    g.DrawRectangle(outlinePen, 6, 8, 20, 18);
                }

                // Compression lines
                using (Pen compressPen = new Pen(Color.FromArgb(160, 82, 45), 1))
                {
                    g.DrawLine(compressPen, 8, 12, 24, 12);
                    g.DrawLine(compressPen, 8, 16, 24, 16);
                    g.DrawLine(compressPen, 8, 20, 24, 20);
                }

                // Zipper
                using (Pen zipPen = new Pen(Color.Silver, 2))
                {
                    g.DrawLine(zipPen, 16, 6, 16, 8);
                }
            }
            return bmp;
        }

        private Bitmap CreateDocumentIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Document background
                using (Brush docBrush = new SolidBrush(Color.FromArgb(70, 130, 180)))
                {
                    Rectangle docRect = new Rectangle(6, 4, 18, 24);
                    g.FillRectangle(docBrush, docRect);
                }

                // Folded corner
                using (Brush cornerBrush = new SolidBrush(Color.FromArgb(100, 149, 237)))
                {
                    Point[] corner = {
                new Point(20, 4),
                new Point(24, 8),
                new Point(20, 8)
            };
                    g.FillPolygon(cornerBrush, corner);
                }

                // White content area
                using (Brush contentBrush = new SolidBrush(Color.White))
                {
                    Rectangle contentRect = new Rectangle(8, 10, 14, 16);
                    g.FillRectangle(contentBrush, contentRect);
                }

                // Text lines
                using (Pen textPen = new Pen(Color.FromArgb(64, 64, 64), 1))
                {
                    g.DrawLine(textPen, 9, 13, 20, 13);
                    g.DrawLine(textPen, 9, 16, 21, 16);
                    g.DrawLine(textPen, 9, 19, 18, 19);
                }
            }
            return bmp;
        }

        private Bitmap CreateSystemFileIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // System file background (red warning)
                using (Brush sysBrush = new SolidBrush(Color.FromArgb(220, 20, 60)))
                {
                    Rectangle sysRect = new Rectangle(6, 4, 18, 24);
                    g.FillRectangle(sysBrush, sysRect);
                }

                // Warning triangle
                using (Brush warnBrush = new SolidBrush(Color.Yellow))
                {
                    Point[] triangle = {
                new Point(15, 8),
                new Point(11, 16),
                new Point(19, 16)
            };
                    g.FillPolygon(warnBrush, triangle);
                }

                // Exclamation mark
                using (Brush exclBrush = new SolidBrush(Color.Red))
                {
                    g.FillRectangle(exclBrush, 14, 10, 2, 4);
                    g.FillRectangle(exclBrush, 14, 15, 2, 1);
                }
            }
            return bmp;
        }

        private Bitmap CreateScriptIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Script background
                using (Brush scriptBrush = new SolidBrush(Color.FromArgb(50, 205, 50)))
                {
                    Rectangle scriptRect = new Rectangle(6, 4, 18, 24);
                    g.FillRectangle(scriptBrush, scriptRect);
                }

                // Code brackets
                using (Brush codeBrush = new SolidBrush(Color.White))
                {
                    Font codeFont = new Font("Consolas", 8, FontStyle.Bold);
                    g.DrawString("{ }", codeFont, codeBrush, 8, 14);
                }

                // Terminal prompt
                using (Pen promptPen = new Pen(Color.White, 1))
                {
                    g.DrawString(">", new Font("Consolas", 6), Brushes.White, 8, 8);
                }
            }
            return bmp;
        }

        private Bitmap CreateDefaultFileIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Default file background
                using (Brush fileBrush = new SolidBrush(Color.FromArgb(211, 211, 211)))
                {
                    Rectangle fileRect = new Rectangle(6, 4, 18, 24);
                    g.FillRectangle(fileBrush, fileRect);
                }

                // File outline
                using (Pen outlinePen = new Pen(Color.Gray, 1))
                {
                    g.DrawRectangle(outlinePen, 6, 4, 18, 24);
                }

                // Generic file symbol
                using (Brush symbolBrush = new SolidBrush(Color.FromArgb(128, 128, 128)))
                {
                    Font symbolFont = new Font("Arial", 10, FontStyle.Bold);
                    g.DrawString("?", symbolFont, symbolBrush, 13, 14);
                }
            }
            return bmp;
        }

        private Bitmap CreateUpArrowIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

                // Up arrow
                using (Brush arrowBrush = new SolidBrush(Color.FromArgb(255, 215, 0)))
                {
                    Point[] arrow = {
                new Point(16, 6),
                new Point(8, 16),
                new Point(12, 16),
                new Point(12, 26),
                new Point(20, 26),
                new Point(20, 16),
                new Point(24, 16)
            };
                    g.FillPolygon(arrowBrush, arrow);
                }

                // Arrow outline
                using (Pen outlinePen = new Pen(Color.FromArgb(218, 165, 32), 1))
                {
                    Point[] arrow = {
                new Point(16, 6),
                new Point(8, 16),
                new Point(12, 16),
                new Point(12, 26),
                new Point(20, 26),
                new Point(20, 16),
                new Point(24, 16)
            };
                    g.DrawPolygon(outlinePen, arrow);
                }
            }
            return bmp;
        }

        private void CreateNavigationPanel()
        {
            navigationPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 45,
                BackColor = Color.FromArgb(45, 45, 48),
                Padding = new Padding(8)
            };

            // Up button
            btnUp = new Button
            {
                Text = "⬆ Up",
                Location = new Point(8, 8),
                Size = new Size(70, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F, FontStyle.Regular)
            };
            btnUp.FlatAppearance.BorderSize = 0;
            btnUp.Click += BtnUp_Click;

            // Home button
            btnHome = new Button
            {
                Text = "🏠 Home",
                Location = new Point(85, 8),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(40, 167, 69),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F, FontStyle.Regular)
            };
            btnHome.FlatAppearance.BorderSize = 0;
            btnHome.Click += BtnHome_Click;

            // Current path textbox
            txtCurrentPath = new TextBox
            {
                Location = new Point(175, 10),
                Size = new Size(700, 26),
                BackColor = Color.FromArgb(60, 60, 60),
                ForeColor = Color.FromArgb(220, 220, 220),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 10F, FontStyle.Regular),
                ReadOnly = false
            };
            txtCurrentPath.KeyPress += TxtCurrentPath_KeyPress;

            // Refresh button
            btnRefresh = new Button
            {
                Text = "🔄",
                Location = new Point(885, 8),
                Size = new Size(40, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 10F, FontStyle.Regular)
            };
            btnRefresh.FlatAppearance.BorderSize = 0;
            btnRefresh.Click += BtnRefresh_Click;

            navigationPanel.Controls.AddRange(new Control[] { btnUp, btnHome, txtCurrentPath, btnRefresh });
        }

        private void CreateToolbarPanel()
        {
            toolbarPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 40,
                BackColor = Color.FromArgb(55, 55, 58),
                Padding = new Padding(8, 5, 8, 5)
            };

            // New Folder button
            btnNewFolder = new Button
            {
                Text = "📁 New Folder",
                Location = new Point(8, 5),
                Size = new Size(100, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(75, 0, 130),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F, FontStyle.Regular)
            };
            btnNewFolder.FlatAppearance.BorderSize = 0;
            btnNewFolder.Click += BtnNewFolder_Click;

            // Upload button
            Button btnUpload = new Button
            {
                Text = "⬆ Upload",
                Location = new Point(115, 5),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(220, 120, 0),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F, FontStyle.Regular)
            };
            btnUpload.FlatAppearance.BorderSize = 0;
            btnUpload.Click += BtnUpload_Click;

            // View mode buttons
            Label lblView = new Label
            {
                Text = "View:",
                Location = new Point(220, 10),
                Size = new Size(40, 20),
                ForeColor = Color.FromArgb(200, 200, 200),
                Font = new Font("Segoe UI", 9F, FontStyle.Regular)
            };

            Button btnDetailsView = new Button
            {
                Text = "Details",
                Location = new Point(265, 5),
                Size = new Size(60, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 8F, FontStyle.Regular)
            };
            btnDetailsView.FlatAppearance.BorderSize = 0;
            btnDetailsView.Click += (s, e) => { lvFiles.View = View.Details; };

            Button btnIconView = new Button
            {
                Text = "Icons",
                Location = new Point(330, 5),
                Size = new Size(50, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 8F, FontStyle.Regular)
            };
            btnIconView.FlatAppearance.BorderSize = 0;
            btnIconView.Click += (s, e) => { lvFiles.View = View.LargeIcon; };

            toolbarPanel.Controls.AddRange(new Control[] { btnNewFolder, btnUpload, lblView, btnDetailsView, btnIconView });
        }

        private void CreateFileListView()
        {
            lvFiles = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                MultiSelect = true,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                AllowDrop = true,
                Font = new Font("Segoe UI", 9F, FontStyle.Regular),
                HideSelection = false
            };

            // Add columns with better widths
            lvFiles.Columns.Add("Name", 350);
            lvFiles.Columns.Add("Size", 100);
            lvFiles.Columns.Add("Type", 120);
            lvFiles.Columns.Add("Modified", 150);
            lvFiles.Columns.Add("Permissions", 100);

            // Event handlers
            lvFiles.DoubleClick += LvFiles_DoubleClick;
            lvFiles.MouseClick += LvFiles_MouseClick;
            lvFiles.DragEnter += LvFiles_DragEnter;
            lvFiles.DragDrop += LvFiles_DragDrop;
            lvFiles.KeyDown += LvFiles_KeyDown;


        }

        private void CreateStatusStrip()
        {
            statusStrip = new StatusStrip
            {
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            statusLabel = new ToolStripStatusLabel
            {
                Text = "Ready",
                ForeColor = Color.FromArgb(220, 220, 220),
                Spring = true,
                TextAlign = ContentAlignment.MiddleLeft
            };

            progressBar = new ToolStripProgressBar
            {
                Size = new Size(200, 16),
                Visible = false
            };

            statusStrip.Items.AddRange(new ToolStripItem[] { statusLabel, progressBar });
        }

        private async void InitializeFileExplorer()
        {
            try
            {
                statusLabel.Text = $"Connecting to beacon {_client.ClientId}...";

                // Verify beacon is connected
                if (!_client.IsConnected)
                {
                    throw new InvalidOperationException($"Beacon {_client.ClientId} is not connected");
                }

                // Clear any existing data
                if (lvFiles != null && !lvFiles.IsDisposed)
                {
                    lvFiles.Items.Clear();
                }

                // Set initial path based on OS
                if (_isLinux)
                {
                    _currentPath = "/"; // Start at root for Linux
                }
                else
                {
                    _currentPath = "C:\\"; // Start at C:\ for Windows
                }

                // Navigate to initial directory on the REMOTE BEACON
                await NavigateToPath(_currentPath);

                statusLabel.Text = $"File Explorer ready for beacon {_client.ClientId}";
            }
            catch (Exception ex)
            {
                string errorMsg = $"Failed to initialise File Explorer for beacon {_client.ClientId}: {ex.Message}";
                statusLabel.Text = "Initialisation failed";
                LogToMainForm($"[!] {errorMsg}", Color.Red);
                MessageBox.Show(errorMsg, "File Explorer Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async Task NavigateToPath(string path)
        {
            if (_isNavigating) return;
            _isNavigating = true;

            try
            {
                // Safety checks
                if (this.IsDisposed || this.Disposing) return;

                // Verify client connection
                if (_client == null || !_client.IsConnected)
                {
                    statusLabel.Text = "Beacon disconnected";
                    LogToMainForm($"[!] Beacon {_client?.ClientId ?? "NULL"} is disconnected", Color.Red);
                    return;
                }

                // Verify server connection
                if (_server == null)
                {
                    statusLabel.Text = "Server unavailable";
                    LogToMainForm("[!] Server is not available", Color.Red);
                    return;
                }

                // Clear current display
                if (lvFiles != null && !lvFiles.IsDisposed)
                {
                    lvFiles.Items.Clear();
                }

                statusLabel.Text = $"Loading {path} from beacon {_client.ClientId}...";
                progressBar.Visible = true;


                // Small delay before sending command
                await Task.Delay(100);

                // Get directory listing from REMOTE BEACON
                string output = await ExecuteDirectoryCommandDirectly(path);

                if (string.IsNullOrEmpty(output))
                {
                    statusLabel.Text = "No response from beacon";
                    LogToMainForm($"[!] No response from beacon {_client.ClientId}", Color.Red);
                    return;
                }

                // Check for errors - but be more lenient
                if (output.Contains("DIRECTORY_ERROR") || output.Contains("Access is denied") ||
                    output.Contains("cannot access") || output.Contains("No such file") ||
                    output.Contains("The system cannot find"))
                {
                    statusLabel.Text = "Directory access error";
                    LogToMainForm($"[!] Directory error on beacon {_client.ClientId}: {output}", Color.Red);

                    string errorMsg = "Failed to access directory. This could be due to:\n" +
                                    "• Permission denied\n" +
                                    "• Path does not exist\n" +
                                    "• Connection issues\n" +
                                    "• Antivirus blocking access\n\n" +
                                    $"Raw output: {output.Substring(0, Math.Min(200, output.Length))}...";

                    this.Invoke(new Action(() =>
                    {
                        MessageBox.Show(errorMsg, "Directory Access Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }));
                    return;
                }

                // Parse the response
                ParseCompleteDirectoryOutput(output, path);

                // Update UI on success
                if (!this.IsDisposed && !this.Disposing)
                {
                    if (lvFiles != null && !lvFiles.IsDisposed)
                    {
                        _currentPath = path;
                        txtCurrentPath.Text = _currentPath;

                        int itemCount = lvFiles.Items.Count;
                        statusLabel.Text = $"Loaded {itemCount} items from beacon {_client.ClientId}";
                    }
                }
            }
            catch (Exception ex)
            {
                statusLabel.Text = $"Navigation error: {ex.Message}";
                LogToMainForm($"[!] File Explorer navigation error on beacon {_client.ClientId}: {ex.Message}", Color.Red);

                this.Invoke(new Action(() =>
                {
                    MessageBox.Show($"Navigation failed: {ex.Message}", "File Explorer Error",
                                  MessageBoxButtons.OK, MessageBoxIcon.Error);
                }));
            }
            finally
            {
                _isNavigating = false;
                progressBar.Visible = false;
            }
        }

        private async Task<string> ExecuteDirectoryCommandDirectly(string path)
        {
            try
            {
                // Verify client is connected
                if (_client == null || !_client.IsConnected)
                {
                    //  System.Diagnostics.Debug.WriteLine($"ERROR: Client {_client?.ClientId ?? "NULL"} is not connected");
                    return "DIRECTORY_ERROR: Client not connected";
                }

                // Make sure we're connected to the correct client
                if (_server.ActiveClientId != _client.ClientId)
                {
                    LogToMainForm($"[*] File Explorer switching to client {_client.ClientId}", Color.Cyan);
                    _server.ConnectToClient(_client.ClientId);
                    await Task.Delay(500);
                }

                string command;
                bool isPowerShell = !_client.IsEncrypted; // Plain connections typically use PowerShell


                if (_isLinux)
                {
                    // Linux: Simple ls command first
                    command = $"ls -la \"{path}\"";
                }
                else if (isPowerShell)
                {
                    // PowerShell: Start with simple Get-ChildItem
                    command = $"Get-ChildItem -Path '{path}' | Format-Table Name, Mode, Length, LastWriteTime -AutoSize";
                }
                else
                {
                    // CMD: Simple dir command
                    string formattedPath = path;
                    if (path.Length == 2 && path.EndsWith(":"))
                    {
                        formattedPath = path + "\\";
                    }
                    command = $"dir \"{formattedPath}\"";
                }



                // Response collection with shell-specific handling
                var responseCollector = new StringBuilder();
                var responseComplete = new TaskCompletionSource<string>();
                DateTime startTime = DateTime.Now;
                bool hasReceivedData = false;

                EventHandler<OutputMessageEventArgs> outputHandler = (sender, e) =>
                {
                    string message = e.Message?.Trim() ?? "";

                    // Skip empty messages and debug info
                    if (string.IsNullOrWhiteSpace(message) ||
                        message.StartsWith("[") && (message.Contains("Server") || message.Contains("DEBUG")))
                    {
                        return;
                    }

                    // Collect any output that looks like directory listing
                    if (!string.IsNullOrWhiteSpace(message))
                    {
                        responseCollector.AppendLine(message);
                        hasReceivedData = true;

                        if (_isLinux)
                        {
                            // Linux completion detection - any output is good
                            bool hasLinuxContent = !string.IsNullOrWhiteSpace(message);

                            if (hasLinuxContent)
                            {
                                Task.Run(async () =>
                                {
                                    await Task.Delay(1500);
                                    responseComplete.TrySetResult(responseCollector.ToString());
                                });
                            }
                        }
                        else if (isPowerShell)
                        {
                            // PowerShell completion detection - look for any formatted output
                            bool hasPowerShellContent = message.Contains("Mode") || message.Contains("Name") ||
                                                       message.Contains("LastWriteTime") || message.Contains("Directory:") ||
                                                       message.Length > 10; // Any substantial output

                            if (hasPowerShellContent)
                            {
                                Task.Run(async () =>
                                {
                                    await Task.Delay(800);
                                    responseComplete.TrySetResult(responseCollector.ToString());
                                });
                            }
                        }
                        else
                        {
                            // CMD completion detection - look for any directory-like output
                            bool hasCmdContent = message.Contains("Directory of") || message.Contains("/") ||
                                                message.Contains("<DIR>") || message.Contains("bytes") ||
                                                message.Length > 10; // Any substantial output

                            if (hasCmdContent)
                            {
                                Task.Run(async () =>
                                {
                                    await Task.Delay(800);
                                    responseComplete.TrySetResult(responseCollector.ToString());
                                });
                            }
                        }
                    }
                };

                _server.OutputMessage += outputHandler;

                try
                {
                    // Send the command
                    _server.SendCommand(command);

                    // Timeout based on shell type
                    int timeoutMs = isPowerShell ? 8000 : 10000;
                    var timeoutTask = Task.Delay(timeoutMs);
                    var completedTask = await Task.WhenAny(responseComplete.Task, timeoutTask);

                    if (completedTask == timeoutTask)
                    {
                        string partialResponse = responseCollector.ToString();

                        LogToMainForm($"[WARNING] Timeout occurred. Collected {partialResponse.Length} characters", Color.Yellow);
                        //   LogToMainForm($"[DEBUG] Partial response: {partialResponse.Substring(0, Math.Min(300, partialResponse.Length))}", Color.Gray);

                        if (hasReceivedData && partialResponse.Length > 10)
                        {
                            LogToMainForm("[*] Using partial response from timeout", Color.Yellow);
                            return partialResponse;
                        }
                        else
                        {
                            // Try one more simple command as last resort
                            LogToMainForm("[*] Trying fallback command...", Color.Yellow);
                            responseCollector.Clear();

                            string fallbackCommand;
                            if (_isLinux)
                            {
                                fallbackCommand = "ls";
                            }
                            else if (isPowerShell)
                            {
                                fallbackCommand = "ls"; // PowerShell also supports ls
                            }
                            else
                            {
                                fallbackCommand = "dir /b"; // Bare format
                            }

                            _server.SendCommand(fallbackCommand);
                            await Task.Delay(1000);

                            string fallbackResponse = responseCollector.ToString();
                            if (!string.IsNullOrEmpty(fallbackResponse))
                            {
                                LogToMainForm($"[+] Fallback command worked! Got {fallbackResponse.Length} characters", Color.Green);
                                return fallbackResponse;
                            }

                            LogToMainForm($"[!] File Explorer timeout with no response from {_client.ClientId}", Color.Red);
                            return "DIRECTORY_ERROR: Timeout - no response from beacon";
                        }
                    }

                    string result = await responseComplete.Task;

                    return result ?? "DIRECTORY_ERROR: Empty response";
                }
                finally
                {
                    _server.OutputMessage -= outputHandler;
                }
            }
            catch (Exception ex)
            {
                LogToMainForm($"[!] File Explorer error: {ex.Message}", Color.Red);
                return $"DIRECTORY_ERROR: {ex.Message}";
            }
        }

        private void ParseCompleteDirectoryOutput(string output, string currentPath)
        {
            try
            {
                if (this.IsDisposed || this.Disposing || lvFiles == null || lvFiles.IsDisposed)
                {
                    return;
                }



                var allLines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                // Clear ListView
                lvFiles.Items.Clear();

                int itemCount = 0;

                if (!IsRootPath(currentPath))
                {
                    CreateParentDirectoryItem();
                    itemCount++;
                }

                // For Windows, detect the output format and use appropriate parser
                if (_isLinux)
                {
                    itemCount += ParseLinuxDirectoryOutput(allLines, currentPath);
                }
                else
                {
                    // Check if this looks like PowerShell Format-Table output
                    bool isPowerShellTable = false;
                    foreach (string line in allLines)
                    {
                        if (line.Contains("Name") && line.Contains("Mode") && line.Contains("LastWriteTime"))
                        {
                            isPowerShellTable = true;
                            break;
                        }
                    }


                    if (isPowerShellTable)
                    {
                        itemCount += ParsePowerShellDirectoryOutput(allLines, currentPath);
                    }
                    else
                    {
                        // Try CMD parser first
                        int cmdItems = ParseWindowsDirectoryOutput(allLines, currentPath);
                        if (cmdItems > 0)
                        {
                            itemCount += cmdItems;
                        }
                        else
                        {
                            itemCount += ParseGenericOutput(allLines, currentPath);
                        }
                    }
                }


                // Force refresh
                if (lvFiles != null && !lvFiles.IsDisposed)
                {
                    lvFiles.Refresh();
                }
            }
            catch (Exception ex)
            {
                LogToMainForm($"[!] Parsing error: {ex.Message}", Color.Red);
            }
        }
        private bool CreatePowerShellFileListViewItem(string fileName, bool isDirectory, string length, string dateTime, string currentPath)
        {
            try
            {
                if (this.IsDisposed || this.Disposing || lvFiles == null || lvFiles.IsDisposed)
                {
                    return false;
                }

                // Skip current and parent directory entries (we add parent manually)
                if (fileName == "." || fileName == "..") return false;

                // Create item with display name
                var item = new ListViewItem(fileName);

                // Set icon index
                item.ImageIndex = isDirectory ? 0 : GetFileIconIndex(fileName, isDirectory, "");

                // Size
                if (isDirectory)
                {
                    item.SubItems.Add("<DIR>");
                }
                else
                {
                    if (!string.IsNullOrEmpty(length) && long.TryParse(length, out long size))
                    {
                        item.SubItems.Add(FormatFileSize(size));
                    }
                    else
                    {
                        item.SubItems.Add("");
                    }
                }

                // Type
                string fileType = isDirectory ? "Directory" : GetFileType(fileName);
                item.SubItems.Add(fileType);

                // Modified date/time
                item.SubItems.Add(dateTime);

                // Permissions (simplified)
                item.SubItems.Add(isDirectory ? "d" : "-");

                // Create full path
                string fullPath = Path.Combine(currentPath, fileName);

                // Tag with file information
                item.Tag = new EnhancedFileItem
                {
                    Name = fileName,
                    IsDirectory = isDirectory,
                    Size = length,
                    FullPath = fullPath
                };

                // Apply colors
                if (isDirectory)
                {
                    item.ForeColor = Color.FromArgb(100, 149, 237);
                    item.Font = new Font(lvFiles.Font, FontStyle.Bold);
                }
                else
                {
                    item.ForeColor = Color.FromArgb(220, 220, 220);
                }

                // Add to ListView
                lvFiles.Items.Add(item);
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error creating PowerShell item: {ex.Message}");
                return false;
            }
        }

        private int ParseGenericOutput(string[] lines, string currentPath)
        {
            int itemCount = 0;

            foreach (string line in lines)
            {
                string cleanLine = line.Trim();

                // Skip obvious system messages
                if (string.IsNullOrEmpty(cleanLine) ||
                    cleanLine.StartsWith("Volume") ||
                    cleanLine.StartsWith("Directory of") ||
                    cleanLine.Contains("File(s)") ||
                    cleanLine.Contains("Dir(s)") ||
                    cleanLine.Contains("bytes") ||
                    cleanLine.Contains("Total") ||
                    cleanLine.Length < 3)
                {
                    continue;
                }


                string fileName = "";
                bool isDirectory = false;

                // If line contains obvious directory indicators
                if (cleanLine.Contains("DIR") || cleanLine.Contains("folder", StringComparison.OrdinalIgnoreCase))
                {
                    isDirectory = true;
                    var parts = cleanLine.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    fileName = parts[parts.Length - 1]; // Take last part as filename
                }
                else
                {
                    // Try to find filename - take the last part that looks like a filename
                    var parts = cleanLine.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

                    // Look for the part that looks most like a filename
                    for (int i = parts.Length - 1; i >= 0; i--)
                    {
                        string part = parts[i];

                        // Skip obvious size/date parts
                        if (Regex.IsMatch(part, @"^\d+$") || // Just numbers
                            Regex.IsMatch(part, @"^\d{1,2}/\d{1,2}/\d{4}$") || // Date
                            Regex.IsMatch(part, @"^\d{1,2}:\d{2}$") || // Time
                            part.Contains("AM") || part.Contains("PM") ||
                            part.Contains(",") && Regex.IsMatch(part, @"^\d+,\d+"))
                        {
                            continue;
                        }

                        // This looks like a filename
                        fileName = part;
                        break;
                    }
                }

                // If we found something that looks like a filename
                if (!string.IsNullOrEmpty(fileName) && fileName != "." && fileName != "..")
                {
                    try
                    {
                        var item = new ListViewItem(fileName);
                        item.ImageIndex = isDirectory ? 0 : 9; // Folder or default icon
                        item.SubItems.Add(isDirectory ? "<DIR>" : "");
                        item.SubItems.Add(isDirectory ? "Directory" : "File");
                        item.SubItems.Add(""); // Date
                        item.SubItems.Add(""); // Permissions

                        string fullPath = Path.Combine(currentPath, fileName);
                        item.Tag = new EnhancedFileItem
                        {
                            Name = fileName,
                            IsDirectory = isDirectory,
                            Size = "",
                            FullPath = fullPath
                        };

                        if (isDirectory)
                        {
                            item.ForeColor = Color.FromArgb(100, 149, 237);
                            item.Font = new Font(lvFiles.Font, FontStyle.Bold);
                        }

                        lvFiles.Items.Add(item);
                        itemCount++;
                    }
                    catch (Exception ex)
                    {
                    }
                }
            }

            return itemCount;
        }
        private bool IsRootPath(string path)
        {
            if (_isLinux)
            {
                return path == "/";
            }
            else
            {
                return path.Length <= 3 && path.EndsWith("\\"); // C:\ etc.
            }
        }

        private void CreateParentDirectoryItem()
        {
            try
            {
                var parentItem = new ListViewItem("..");
                parentItem.ImageIndex = 10; // Up arrow icon
                parentItem.SubItems.Add("<DIR>");
                parentItem.SubItems.Add("Parent Directory");
                parentItem.SubItems.Add("");
                parentItem.SubItems.Add("");

                parentItem.Tag = new EnhancedFileItem
                {
                    Name = "..",
                    IsDirectory = true,
                    Size = "",
                    FullPath = GetParentPath(_currentPath)
                };

                parentItem.ForeColor = Color.Yellow;
                parentItem.Font = new Font(lvFiles.Font, FontStyle.Bold);

                lvFiles.Items.Add(parentItem);
            }
            catch (Exception ex)
            {
            }
        }

        private int ParsePowerShellDirectoryOutput(string[] lines, string currentPath)
        {
            int itemCount = 0;
            bool inDataSection = false;
            bool foundHeader = false;


            foreach (string line in lines)
            {
                string cleanLine = line.Trim();

                // Skip empty lines, command echoes, and system messages
                if (string.IsNullOrEmpty(cleanLine) ||
                    cleanLine.StartsWith("[") ||  // Skip timestamp lines
                    cleanLine.Contains("Get-ChildItem") ||
                    cleanLine.Contains("PowerShell commands") ||
                    cleanLine.Contains("Consider using") ||
                    cleanLine.Contains("PS C:\\") ||
                    cleanLine.Length < 3)
                {
                    continue;
                }


                // Look for the header line
                if (cleanLine.StartsWith("Name") && cleanLine.Contains("Mode"))
                {
                    foundHeader = true;
                    continue;
                }

                // Look for the separator line
                if (cleanLine.StartsWith("----") && foundHeader)
                {
                    inDataSection = true;
                    continue;
                }

                // Parse data lines after we've found the header and separator
                if (inDataSection && foundHeader)
                {

                    var match = Regex.Match(cleanLine,
                        @"^([^\s]+(?:\s+[^\s]+)*)\s+(d[r-]{5}|[a-z-]{6})\s+(\d*)\s*(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)$");

                    if (match.Success)
                    {
                        string fileName = match.Groups[1].Value.Trim();
                        string mode = match.Groups[2].Value;
                        string length = match.Groups[3].Value;
                        string dateTime = match.Groups[4].Value;

                        bool isDirectory = mode.StartsWith("d");


                        // Create ListView item
                        if (CreatePowerShellFileListViewItem(fileName, isDirectory, length, dateTime, currentPath))
                        {
                            itemCount++;
                        }
                    }
                    else
                    {

                        var simpleParts = cleanLine.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

                        if (simpleParts.Length >= 2)
                        {
                            string fileName = simpleParts[0];
                            string mode = simpleParts[1];
                            bool isDirectory = mode.StartsWith("d");

                            // Don't include obvious time stamps or PS prompts as files
                            if (!Regex.IsMatch(fileName, @"^\d{1,2}:\d{2}:\d{2}$") &&
                                !fileName.Contains("C:\\") &&
                                !fileName.StartsWith("----"))
                            {

                                if (CreatePowerShellFileListViewItem(fileName, isDirectory, "", "", currentPath))
                                {
                                    itemCount++;
                                }
                            }
                        }
                    }
                }
            }

            return itemCount;
        }

        private int ParseLinuxDirectoryOutput(string[] lines, string currentPath)
        {
            int itemCount = 0;

            foreach (string line in lines)
            {
                string cleanLine = line.Trim();

                // Skip empty lines, total line, debug messages, and error messages
                if (string.IsNullOrEmpty(cleanLine) ||
                    cleanLine.StartsWith("total ") ||
                    cleanLine.Contains("DIRECTORY_ERROR") ||
                    cleanLine.StartsWith("[") ||
                    cleanLine.Contains("File Explorer") ||
                    cleanLine.Contains("DEBUG") ||
                    cleanLine.Length < 10)
                {
                    continue;
                }
                var match = Regex.Match(cleanLine,
                    @"^([dlrwxs-]{10})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\w{3}\s+\d{1,2}\s+(?:\d{4}|\d{1,2}:\d{2}))\s+(.+)$");

                if (match.Success)
                {
                    string permissions = match.Groups[1].Value;
                    string linkCount = match.Groups[2].Value;
                    string owner = match.Groups[3].Value;
                    string group = match.Groups[4].Value;
                    string size = match.Groups[5].Value;
                    string dateTime = match.Groups[6].Value;
                    string fileName = match.Groups[7].Value.Trim();

                    System.Diagnostics.Debug.WriteLine($"MATCHED: perms='{permissions}' file='{fileName}'");

                    // Handle symlinks (name -> target)
                    string linkTarget = "";
                    if (fileName.Contains(" -> "))
                    {
                        var parts = fileName.Split(new[] { " -> " }, 2, StringSplitOptions.None);
                        fileName = parts[0];
                        linkTarget = parts[1];
                    }

                    // Skip current directory
                    if (fileName == ".") continue;

                    // Create ListView item
                    if (CreateLinuxFileListViewItem(fileName, permissions, owner, group, size, dateTime, linkTarget, currentPath))
                    {
                        itemCount++;
                    }
                }
                else
                {
                }
            }

            return itemCount;
        }
        private int ParseWindowsDirectoryOutput(string[] lines, string currentPath)
        {
            int itemCount = 0;

            foreach (string line in lines)
            {
                string cleanLine = line.Trim();

                // Skip system messages and empty lines
                if (string.IsNullOrEmpty(cleanLine) ||
                    cleanLine.StartsWith("Volume in drive") ||
                    cleanLine.StartsWith("Volume Serial Number") ||
                    cleanLine.StartsWith("Directory of") ||
                    cleanLine.Contains("File(s)") ||
                    cleanLine.Contains("Dir(s)") ||
                    cleanLine.Contains("bytes free") ||
                    cleanLine.Contains("DIRECTORY_ERROR") ||
                    cleanLine.Length < 20)
                {
                    continue;
                }

                // Parse Windows directory entry
                var match = Regex.Match(cleanLine,
                    @"^(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}\s+[AP]M)\s+(<DIR>|<JUNCTION>|<SYMLINKD>|\d+(?:,\d{3})*)\s+(.+)$",
                    RegexOptions.IgnoreCase);

                if (match.Success)
                {
                    string datePart = match.Groups[1].Value;
                    string timePart = match.Groups[2].Value;
                    string sizePart = match.Groups[3].Value;
                    string fileName = match.Groups[4].Value.Trim();

                    // Handle junction names with brackets
                    if (sizePart.Contains("JUNCTION") && fileName.Contains("["))
                    {
                        int bracketPos = fileName.IndexOf("[");
                        if (bracketPos > 0)
                        {
                            fileName = fileName.Substring(0, bracketPos).Trim();
                        }
                    }

                    // Skip current directory and already added parent
                    if (fileName == "." || fileName == "..") continue;

                    // Create ListView item
                    if (CreateFileListViewItem(fileName, sizePart, datePart, timePart, currentPath))
                    {
                        itemCount++;
                    }
                }
                else
                {
                }
            }

            return itemCount;
        }
        private bool CreateLinuxFileListViewItem(string fileName, string permissions, string owner, string group,
     string size, string dateTime, string linkTarget, string currentPath)
        {
            try
            {
                if (this.IsDisposed || this.Disposing || lvFiles == null || lvFiles.IsDisposed)
                {
                    return false;
                }

                // Determine file type from permissions
                bool isDirectory = permissions.StartsWith("d");
                bool isSymlink = permissions.StartsWith("l");

                // Create item with display name
                var item = new ListViewItem(fileName);

                // Set icon index
                item.ImageIndex = GetLinuxFileIconIndex(fileName, permissions, isDirectory);

                // Size (format for readability)
                if (isDirectory)
                {
                    item.SubItems.Add("<DIR>");
                }
                else
                {
                    item.SubItems.Add(FormatFileSize(long.TryParse(size, out long sizeBytes) ? sizeBytes : 0));
                }

                // File type
                string fileType = GetLinuxFileType(permissions, fileName);
                item.SubItems.Add(fileType);

                // Modified date/time
                item.SubItems.Add(dateTime);

                // Permissions (readable format)
                item.SubItems.Add(FormatLinuxPermissions(permissions));

                // Create full path
                string fullPath;
                if (fileName == "..")
                {
                    fullPath = GetParentPath(currentPath);
                }
                else if (isSymlink && !string.IsNullOrEmpty(linkTarget))
                {
                    fullPath = linkTarget.StartsWith("/") ? linkTarget : Path.Combine(currentPath, linkTarget).Replace('\\', '/');
                }
                else
                {
                    fullPath = Path.Combine(currentPath, fileName).Replace('\\', '/');
                    if (fullPath.StartsWith("//")) fullPath = fullPath.Substring(1);
                }

                // Tag with file information
                item.Tag = new EnhancedFileItem
                {
                    Name = fileName,
                    IsDirectory = isDirectory,
                    Size = size,
                    FullPath = fullPath
                };

                // Apply colours and formatting
                ApplyLinuxFileColors(item, permissions, fileName, isSymlink, linkTarget);

                // Add to ListView
                lvFiles.Items.Add(item);
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        private int GetLinuxFileIconIndex(string fileName, string permissions, bool isDirectory)
        {
            if (fileName == "..")
                return 10; // Up arrow

            if (isDirectory)
                return 0; // Folder icon

            if (permissions.StartsWith("l"))
                return 1; // Symlink/junction icon

            if (permissions.Contains("x")) // Executable
                return 3; // Executable icon

            string extension = Path.GetExtension(fileName).ToLower();
            return extension switch
            {
                ".txt" or ".log" or ".conf" or ".cfg" => 2, // Text
                ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" => 4, // Image
                ".tar" or ".gz" or ".zip" or ".bz2" or ".xz" => 5, // Archive
                ".pdf" or ".doc" or ".odt" => 6, // Document
                ".so" or ".ko" => 7, // System/library
                ".sh" or ".py" or ".pl" or ".rb" => 8, // Script
                _ => 9 // Default
            };
        }


        private string GetLinuxFileType(string permissions, string fileName)
        {
            if (permissions.StartsWith("d")) return "Directory";
            if (permissions.StartsWith("l")) return "Symlink";
            if (permissions.StartsWith("b")) return "Block Device";
            if (permissions.StartsWith("c")) return "Char Device";
            if (permissions.StartsWith("s")) return "Socket";
            if (permissions.StartsWith("p")) return "Named Pipe";

            if (permissions.Contains("x"))
                return "Executable";

            string extension = Path.GetExtension(fileName).ToLower();
            return extension switch
            {
                ".txt" or ".log" => "Text File",
                ".sh" => "Shell Script",
                ".py" => "Python Script",
                ".conf" or ".cfg" => "Configuration",
                ".so" => "Shared Library",
                "" => "File",
                _ => $"{extension.TrimStart('.')} File"
            };
        }


        private string FormatLinuxPermissions(string permissions)
        {
            if (permissions.Length < 10) return permissions;

            string fileType = permissions[0].ToString();
            string owner = permissions.Substring(1, 3);
            string group = permissions.Substring(4, 3);
            string other = permissions.Substring(7, 3);

            return $"{fileType}{owner} {group} {other}";
        }


        private void ApplyLinuxFileColors(ListViewItem item, string permissions, string fileName, bool isSymlink, string linkTarget)
        {
            if (fileName == "..")
            {
                item.ForeColor = Color.Yellow;
                item.Font = new Font(lvFiles.Font, FontStyle.Bold);
            }
            else if (permissions.StartsWith("d")) // Directory
            {
                item.ForeColor = Color.FromArgb(100, 149, 237); // Light blue
                item.Font = new Font(lvFiles.Font, FontStyle.Bold);
            }
            else if (isSymlink) // Symlink
            {
                item.ForeColor = Color.FromArgb(0, 255, 255); // Cyan
            }
            else if (permissions.Contains("x")) // Executable
            {
                item.ForeColor = Color.FromArgb(0, 255, 0); // Green
            }
            else if (fileName.StartsWith(".")) // Hidden files
            {
                item.ForeColor = Color.Gray;
            }
            else
            {
                item.ForeColor = Color.FromArgb(220, 220, 220); // Default white
            }
        }

        private bool CreateFileListViewItem(string fileName, string sizeType, string date, string time, string currentPath)
        {
            try
            {
                if (this.IsDisposed || this.Disposing || lvFiles == null || lvFiles.IsDisposed)
                {
                    return false;
                }

                // Determine type
                bool isDirectory = sizeType.Contains("DIR") || sizeType.Contains("JUNCTION") || sizeType.Contains("SYMLINKD");
                bool isJunction = sizeType.Contains("JUNCTION") || sizeType.Contains("SYMLINKD");

                // Handle junction paths
                string displayName = fileName;
                string targetPath = null;

                if (isJunction && fileName.Contains("[") && fileName.Contains("]"))
                {
                    int bracketStart = fileName.IndexOf("[");
                    int bracketEnd = fileName.IndexOf("]");

                    if (bracketStart > 0 && bracketEnd > bracketStart)
                    {
                        displayName = fileName.Substring(0, bracketStart).Trim();
                        targetPath = fileName.Substring(bracketStart + 1, bracketEnd - bracketStart - 1).Trim();
                    }
                }

                // Create item with display name
                var item = new ListViewItem(displayName);

                // Set icon index
                item.ImageIndex = GetFileIconIndex(displayName, isDirectory, sizeType);

                // Size
                if (isDirectory)
                {
                    item.SubItems.Add(sizeType);
                }
                else
                {
                    // Handle numeric sizes (remove commas and format)
                    if (long.TryParse(sizeType.Replace(",", ""), out long size))
                    {
                        item.SubItems.Add(FormatFileSize(size));
                    }
                    else
                    {
                        item.SubItems.Add(sizeType);
                    }
                }

                // Type
                string fileType = "File";
                if (sizeType.Contains("DIR")) fileType = "Folder";
                else if (sizeType.Contains("JUNCTION")) fileType = "Junction";
                else if (sizeType.Contains("SYMLINKD")) fileType = "Symlink";
                else if (!isDirectory) fileType = GetFileType(displayName);

                item.SubItems.Add(fileType);

                // Modified
                item.SubItems.Add($"{date} {time}");

                // Permissions
                item.SubItems.Add(isDirectory ? "d" : "-");

                // Create full path - use target path for junctions
                string fullPath;
                if (isJunction && !string.IsNullOrEmpty(targetPath))
                {
                    fullPath = targetPath; // Use the actual target path
                }
                else
                {
                    fullPath = Path.Combine(currentPath, displayName);
                }

                // Tag with proper paths
                item.Tag = new EnhancedFileItem
                {
                    Name = displayName,
                    IsDirectory = isDirectory,
                    Size = isDirectory ? "" : sizeType,
                    FullPath = fullPath
                };

                // Apply colors
                if (displayName == "..")
                {
                    item.ForeColor = Color.Yellow;
                    item.Font = new Font(lvFiles.Font, FontStyle.Bold);
                }
                else if (fileType == "Folder")
                {
                    item.ForeColor = Color.FromArgb(100, 149, 237);
                    item.Font = new Font(lvFiles.Font, FontStyle.Bold);
                }
                else if (fileType == "Junction" || fileType == "Symlink")
                {
                    item.ForeColor = Color.FromArgb(255, 165, 0);
                    item.Font = new Font(lvFiles.Font, FontStyle.Bold);
                }

                lvFiles.Items.Add(item);
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        private string FormatFileSizeFromString(string sizeStr)
        {
            if (string.IsNullOrEmpty(sizeStr) || !long.TryParse(sizeStr.Replace(",", ""), out long size))
                return sizeStr;

            return FormatFileSize(size);
        }

        private string FormatFileSize(long size)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            double fileSize = size;
            int suffixIndex = 0;

            while (fileSize >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                fileSize /= 1024;
                suffixIndex++;
            }

            return $"{fileSize:N1} {suffixes[suffixIndex]}";
        }
        private string GetFileType(string fileName)
        {
            string extension = Path.GetExtension(fileName).ToLower();
            return extension switch
            {
                ".txt" => "Text Document",
                ".exe" => "Application",
                ".dll" => "Dynamic Library",
                ".pdf" => "PDF Document",
                ".doc" or ".docx" => "Word Document",
                ".xls" or ".xlsx" => "Excel Spreadsheet",
                ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" => "Image",
                ".mp4" or ".avi" or ".mkv" or ".mov" => "Video",
                ".mp3" or ".wav" or ".flac" => "Audio",
                ".zip" or ".rar" or ".7z" or ".tar" or ".gz" => "Archive",
                ".html" or ".htm" => "Web Page",
                ".css" => "Stylesheet",
                ".js" => "JavaScript",
                ".py" => "Python Script",
                ".cs" => "C# Source",
                ".cpp" or ".c" => "C/C++ Source",
                ".java" => "Java Source",
                ".xml" => "XML Document",
                ".json" => "JSON Data",
                ".log" => "Log File",
                ".ini" or ".cfg" => "Configuration",
                "" => "File",
                _ => $"{extension.TrimStart('.')} File"
            };
        }
        private int GetFileIconIndex(string fileName, bool isDirectory, string sizeType)
        {
            if (fileName == "..")
                return 10; // Up arrow

            if (isDirectory)
            {
                if (sizeType.Contains("JUNCTION") || sizeType.Contains("SYMLINKD"))
                    return 1; // Junction
                else
                    return 0; // Folder
            }

            string extension = Path.GetExtension(fileName).ToLower();

            return extension switch
            {
                ".txt" or ".log" or ".ini" or ".cfg" or ".conf" => 2, // Text
                ".exe" or ".msi" or ".com" => 3, // Executable
                ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".tiff" or ".ico" => 4, // Image
                ".zip" or ".rar" or ".7z" or ".tar" or ".gz" or ".bz2" => 5, // Archive
                ".doc" or ".docx" or ".pdf" or ".xls" or ".xlsx" or ".ppt" or ".pptx" => 6, // Document
                ".dll" or ".sys" or ".drv" or ".ocx" => 7, // System
                ".bat" or ".cmd" or ".ps1" or ".vbs" or ".js" or ".py" or ".sh" => 8, // Script
                _ => 9 // Default
            };
        }
        private string GetParentPath(string path)
        {
            if (_isLinux)
            {
                if (path == "/") return "/";
                path = path.TrimEnd('/');
                int lastSlash = path.LastIndexOf('/');
                if (lastSlash <= 0) return "/";
                return path.Substring(0, lastSlash);
            }
            else
            {
                if (path.Length <= 3) return path;
                return Directory.GetParent(path)?.FullName ?? path;
            }
        }
        #region Event Handlers

        private async void LvFiles_DoubleClick(object sender, EventArgs e)
        {
            if (lvFiles.SelectedItems.Count != 1) return;

            var selectedItem = lvFiles.SelectedItems[0];
            var fileItem = (EnhancedFileItem)selectedItem.Tag;

            if (fileItem.IsDirectory)
            {
                string newPath;

                if (fileItem.Name == "..")
                {
                    newPath = GetParentPath(_currentPath);
                }
                else
                {
                    if (selectedItem.SubItems[2].Text == "Junction" || selectedItem.SubItems[2].Text == "Symlink")
                    {
                        newPath = fileItem.FullPath;
                    }
                    else
                    {
                        // Regular directory
                        if (_isLinux)
                        {
                            newPath = _currentPath.TrimEnd('/') + "/" + fileItem.Name;
                            if (newPath.StartsWith("//")) newPath = newPath.Substring(1);
                        }
                        else
                        {
                            newPath = Path.Combine(_currentPath, fileItem.Name);
                        }
                    }
                }

                await NavigateToPath(newPath);
            }
        }

        private void CreateContextMenu()
        {
            contextMenuFiles = new ContextMenuStrip
            {
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Font = new Font("Segoe UI", 9F, FontStyle.Regular)
            };

            // Download
            downloadMenuItem = new ToolStripMenuItem("📥 Download")
            {
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Name = "downloadMenuItem"
            };
            downloadMenuItem.Click += DownloadMenuItem_Click;

            // Upload
            uploadMenuItem = new ToolStripMenuItem("📤 Upload Here")
            {
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };
            uploadMenuItem.Click += UploadMenuItem_Click;

            var separator1 = new ToolStripSeparator();

            // New Folder/Directory
            newFolderMenuItem = new ToolStripMenuItem(_isLinux ? "📁 New Directory" : "📁 New Folder")
            {
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };
            newFolderMenuItem.Click += NewFolderMenuItem_Click;

            // Linux-specific: Permissions
            if (_isLinux)
            {
                permissionsMenuItem = new ToolStripMenuItem("🔐 Permissions")
                {
                    BackColor = Color.FromArgb(45, 45, 48),
                    ForeColor = Color.FromArgb(220, 220, 220)
                };
                permissionsMenuItem.Click += PermissionsMenuItem_Click;
            }

            // Linux-specific: Create Symlink
            if (_isLinux)
            {
                symlinkMenuItem = new ToolStripMenuItem("🔗 Create Symlink")
                {
                    BackColor = Color.FromArgb(45, 45, 48),
                    ForeColor = Color.FromArgb(220, 220, 220)
                };
                symlinkMenuItem.Click += SymlinkMenuItem_Click;
            }

            // Delete
            deleteMenuItem = new ToolStripMenuItem("🗑️ Delete")
            {
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };
            deleteMenuItem.Click += DeleteMenuItem_Click;

            var separator2 = new ToolStripSeparator();

            // Copy Path
            copyPathMenuItem = new ToolStripMenuItem("📋 Copy Path")
            {
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };
            copyPathMenuItem.Click += CopyPathMenuItem_Click;

            // Properties
            propertiesMenuItem = new ToolStripMenuItem("ℹ️ Properties")
            {
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };
            propertiesMenuItem.Click += PropertiesMenuItem_Click;

            // Refresh
            refreshMenuItem = new ToolStripMenuItem("🔄 Refresh")
            {
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };
            refreshMenuItem.Click += BtnRefresh_Click;

            // Build menu items list
            var menuItems = new List<ToolStripItem>
            {
                downloadMenuItem,
                uploadMenuItem,
                separator1,
                newFolderMenuItem
            };

            // Add Linux-specific items
            if (_isLinux)
            {
                if (permissionsMenuItem != null) menuItems.Add(permissionsMenuItem);
                if (symlinkMenuItem != null) menuItems.Add(symlinkMenuItem);
            }

            menuItems.AddRange(new ToolStripItem[]
            {
                deleteMenuItem,
                separator2,
                copyPathMenuItem,
                propertiesMenuItem,
                new ToolStripSeparator(),
                refreshMenuItem
            });

            contextMenuFiles.Items.AddRange(menuItems.ToArray());
        }

        private void LvFiles_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {

                bool hasSelection = lvFiles.SelectedItems.Count > 0;
                bool hasFileSelection = false;
                bool hasDirectorySelection = false;

                if (hasSelection)
                {
                    var selectedItem = lvFiles.SelectedItems[0];
                    var fileItem = (EnhancedFileItem)selectedItem.Tag;


                    hasFileSelection = !fileItem.IsDirectory && fileItem.Name != "..";
                    hasDirectorySelection = fileItem.IsDirectory && fileItem.Name != "..";
                }

                // Standard menu items
                downloadMenuItem.Visible = hasFileSelection;
                downloadMenuItem.Enabled = hasFileSelection;

                uploadMenuItem.Visible = true;
                uploadMenuItem.Enabled = true;

                newFolderMenuItem.Visible = true;
                newFolderMenuItem.Enabled = true;

                deleteMenuItem.Visible = hasSelection && lvFiles.SelectedItems[0].Text != "..";
                deleteMenuItem.Enabled = hasSelection && lvFiles.SelectedItems[0].Text != "..";

                copyPathMenuItem.Visible = hasSelection;
                copyPathMenuItem.Enabled = hasSelection;

                propertiesMenuItem.Visible = hasSelection;
                propertiesMenuItem.Enabled = hasSelection;

                // Linux-specific menu items
                if (_isLinux)
                {
                    if (permissionsMenuItem != null)
                    {
                        permissionsMenuItem.Visible = hasSelection && lvFiles.SelectedItems[0].Text != "..";
                        permissionsMenuItem.Enabled = hasSelection && lvFiles.SelectedItems[0].Text != "..";
                    }

                    if (symlinkMenuItem != null)
                    {
                        symlinkMenuItem.Visible = hasSelection && lvFiles.SelectedItems[0].Text != "..";
                        symlinkMenuItem.Enabled = hasSelection && lvFiles.SelectedItems[0].Text != "..";
                    }
                }

            }
        }

        private void PermissionsMenuItem_Click(object sender, EventArgs e)
        {
            if (!_isLinux || lvFiles.SelectedItems.Count == 0) return;

            var selectedItem = lvFiles.SelectedItems[0];
            var fileItem = (EnhancedFileItem)selectedItem.Tag;

            if (fileItem.Name == "..")
            {
                MessageBox.Show("Cannot change permissions of parent directory reference.", "Invalid Selection",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            ShowLinuxPermissionsDialog(fileItem);
        }

        private void SymlinkMenuItem_Click(object sender, EventArgs e)
        {
            if (!_isLinux || lvFiles.SelectedItems.Count == 0) return;

            var selectedItem = lvFiles.SelectedItems[0];
            var fileItem = (EnhancedFileItem)selectedItem.Tag;

            ShowCreateSymlinkDialog(fileItem);
        }

        private void ShowCreateSymlinkDialog(EnhancedFileItem fileItem)
        {
            Form symlinkForm = new Form
            {
                Text = $"Create Symlink - {fileItem.Name}",
                Size = new Size(450, 250),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            Label lblSource = new Label
            {
                Text = $"Source: {fileItem.FullPath}",
                Location = new Point(20, 20),
                Size = new Size(400, 20),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            Label lblTarget = new Label
            {
                Text = "Symlink path:",
                Location = new Point(20, 60),
                Size = new Size(100, 20),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            TextBox txtTarget = new TextBox
            {
                Location = new Point(130, 58),
                Size = new Size(280, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Text = Path.Combine(_currentPath, fileItem.Name + "_link").Replace('\\', '/')
            };

            CheckBox chkSymbolic = new CheckBox
            {
                Text = "Create symbolic link (default is hard link for files)",
                Location = new Point(20, 100),
                Size = new Size(350, 20),
                ForeColor = Color.FromArgb(220, 220, 220),
                Checked = true
            };

            Button btnCreate = new Button
            {
                Text = "Create",
                Location = new Point(200, 140),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White
            };

            Button btnCancel = new Button
            {
                Text = "Cancel",
                Location = new Point(290, 140),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };

            btnCreate.Click += async (s, e) =>
            {
                string targetPath = txtTarget.Text.Trim();
                if (string.IsNullOrEmpty(targetPath))
                {
                    MessageBox.Show("Please enter a target path for the symlink.", "Missing Target",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string linkCommand;
                if (chkSymbolic.Checked)
                {
                    linkCommand = $"ln -s \"{fileItem.FullPath}\" \"{targetPath}\"";
                }
                else
                {
                    linkCommand = $"ln \"{fileItem.FullPath}\" \"{targetPath}\"";
                }

                statusLabel.Text = $"Creating symlink...";
                _server.SendCommand(linkCommand);

                await Task.Delay(1000);
                await NavigateToPath(_currentPath);

                symlinkForm.Close();
                statusLabel.Text = $"Symlink created: {Path.GetFileName(targetPath)}";
            };

            btnCancel.Click += (s, e) => symlinkForm.Close();

            symlinkForm.Controls.AddRange(new Control[] {
                lblSource, lblTarget, txtTarget, chkSymbolic, btnCreate, btnCancel
            });

            symlinkForm.ShowDialog();
        }

        private void LvFiles_KeyDown(object sender, KeyEventArgs e)
        {
            switch (e.KeyCode)
            {
                case Keys.F5:
                    BtnRefresh_Click(sender, e);
                    break;
                case Keys.Delete:
                    if (lvFiles.SelectedItems.Count > 0)
                    {
                        DeleteMenuItem_Click(sender, e);
                    }
                    break;
                case Keys.Back:
                case Keys.F4 when e.Alt:
                    BtnUp_Click(sender, e);
                    break;
                case Keys.Enter:
                    if (lvFiles.SelectedItems.Count == 1)
                    {
                        LvFiles_DoubleClick(sender, e);
                    }
                    break;
            }
        }

        private async void BtnUp_Click(object sender, EventArgs e)
        {
            string parentPath = GetParentPath(_currentPath);
            if (parentPath != _currentPath)
            {
                await NavigateToPath(parentPath);
            }
        }

        private async void BtnHome_Click(object sender, EventArgs e)
        {
            string homePath;
            if (_isLinux)
            {
                // Try to get user's home directory, fallback to root
                homePath = "/";
            }
            else
            {
                homePath = "C:\\";
            }

            await NavigateToPath(homePath);
        }

        private async void BtnRefresh_Click(object sender, EventArgs e)
        {
            await NavigateToPath(_currentPath);
        }

        private async void TxtCurrentPath_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)Keys.Enter)
            {
                e.Handled = true;
                string newPath = txtCurrentPath.Text.Trim();
                if (!string.IsNullOrEmpty(newPath))
                {

                    // Normalise path separators based on OS
                    if (_isLinux)
                    {
                        newPath = newPath.Replace('\\', '/');
                        // Ensure absolute path starts with /
                        if (!newPath.StartsWith("/"))
                        {
                            newPath = "/" + newPath;
                        }
                    }
                    else
                    {
                        newPath = newPath.Replace('/', '\\');
                        if (!newPath.EndsWith("\\") && !newPath.EndsWith(":"))
                        {
                            newPath = newPath.TrimEnd('\\');
                        }
                    }

                    //    System.Diagnostics.Debug.WriteLine($"Normalised path: '{newPath}'");
                    await NavigateToPath(newPath);
                }
            }
        }

        private void BtnPermissions_Click(object sender, EventArgs e)
        {
            if (!_isLinux) return;

            if (lvFiles.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a file or directory to change permissions.", "No Selection",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var selectedItem = lvFiles.SelectedItems[0];
            var fileItem = (EnhancedFileItem)selectedItem.Tag;

            if (fileItem.Name == "..")
            {
                MessageBox.Show("Cannot change permissions of parent directory reference.", "Invalid Selection",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            ShowLinuxPermissionsDialog(fileItem);
        }

        // Linux permissions dialog
        private void ShowLinuxPermissionsDialog(EnhancedFileItem fileItem)
        {
            Form permissionsForm = new Form
            {
                Text = $"Change Permissions - {fileItem.Name}",
                Size = new Size(400, 300),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            Label lblFile = new Label
            {
                Text = $"File: {fileItem.Name}",
                Location = new Point(20, 20),
                Size = new Size(350, 20),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            Label lblPermissions = new Label
            {
                Text = "Permissions (octal):",
                Location = new Point(20, 60),
                Size = new Size(120, 20),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            TextBox txtPermissions = new TextBox
            {
                Location = new Point(150, 58),
                Size = new Size(100, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Text = "755" // Default permissions
            };

            Label lblExample = new Label
            {
                Text = "Examples: 755 (rwxr-xr-x), 644 (rw-r--r--), 777 (rwxrwxrwx)",
                Location = new Point(20, 90),
                Size = new Size(350, 40),
                ForeColor = Color.FromArgb(150, 150, 150),
                Font = new Font(permissionsForm.Font.FontFamily, 8)
            };

            CheckBox chkRecursive = new CheckBox
            {
                Text = "Apply recursively (directories only)",
                Location = new Point(20, 140),
                Size = new Size(300, 20),
                ForeColor = Color.FromArgb(220, 220, 220),
                Enabled = fileItem.IsDirectory
            };

            Button btnApply = new Button
            {
                Text = "Apply",
                Location = new Point(150, 180),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White
            };

            Button btnCancel = new Button
            {
                Text = "Cancel",
                Location = new Point(240, 180),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };

            btnApply.Click += async (s, e) =>
            {
                string permissions = txtPermissions.Text.Trim();
                if (Regex.IsMatch(permissions, @"^[0-7]{3,4}$"))
                {
                    string chmodCommand = $"chmod {(chkRecursive.Checked ? "-R " : "")}{permissions} \"{fileItem.FullPath}\"";

                    statusLabel.Text = $"Changing permissions for {fileItem.Name}...";
                    _server.SendCommand(chmodCommand);

                    await Task.Delay(1000);
                    await NavigateToPath(_currentPath); // Refresh

                    permissionsForm.Close();
                    statusLabel.Text = $"Permissions changed for {fileItem.Name}";
                }
                else
                {
                    MessageBox.Show("Please enter valid octal permissions (e.g., 755, 644)", "Invalid Permissions",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };

            btnCancel.Click += (s, e) => permissionsForm.Close();

            permissionsForm.Controls.AddRange(new Control[] {
                lblFile, lblPermissions, txtPermissions, lblExample, chkRecursive, btnApply, btnCancel
            });

            permissionsForm.ShowDialog();
        }

        private async void BtnNewFolder_Click(object sender, EventArgs e)
        {
            await CreateNewFolder();
        }

        private void BtnUpload_Click(object sender, EventArgs e)
        {
            UploadMenuItem_Click(sender, e);
        }

        private void LogToMainForm(string message, Color color)
        {
            try
            {
                if (_mainForm != null && !_mainForm.IsDisposed)
                {
                    _mainForm.Invoke(new Action(() =>
                    {
                        var logMethod = _mainForm.GetType().GetMethod("LogMessage",
                            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                        logMethod?.Invoke(_mainForm, new object[] { message, color });
                    }));
                }
            }
            catch (Exception ex)
            {
            }
        }

        private async void DownloadMenuItem_Click(object sender, EventArgs e)
        {

            if (lvFiles.SelectedItems.Count == 0)
            {
                MessageBox.Show("No files selected for download", "No Selection", MessageBoxButtons.OK, MessageBoxIcon.Information);
                LogToMainForm("[!] No files selected for download", Color.Red);
                return;
            }

            // Filter to only get file selections (not directories)
            var selectedFiles = lvFiles.SelectedItems.Cast<ListViewItem>()
                .Where(item =>
                {
                    var fileItem = (EnhancedFileItem)item.Tag;
                    bool isFile = !fileItem.IsDirectory && fileItem.Name != "..";
                    return isFile;
                })
                .ToList();

            if (selectedFiles.Count == 0)
            {
                MessageBox.Show("Please select files (not directories) to download", "Invalid Selection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                LogToMainForm("[!] Please select files (not directories) to download", Color.Red);
                return;
            }


            progressBar.Visible = true;
            progressBar.Maximum = selectedFiles.Count;
            progressBar.Value = 0;

            int successCount = 0;
            int failCount = 0;

            foreach (ListViewItem item in selectedFiles)
            {
                var fileItem = (EnhancedFileItem)item.Tag;


                try
                {
                    await _server.DownloadFile(fileItem.FullPath);

                    successCount++;
                }
                catch (Exception ex)
                {
                    string errorMsg = $"Failed to download {fileItem.Name}: {ex.Message}";
                    statusLabel.Text = errorMsg;

                    LogToMainForm($"[!] {errorMsg}", Color.Red);
                    failCount++;

                    if (selectedFiles.Count == 1)
                    {
                        MessageBox.Show(errorMsg, "Download Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }

                progressBar.Value++;
                await Task.Delay(100); // Small delay for UI updates
            }

            progressBar.Visible = false;

            // Proper completion message based on results
            if (successCount > 0 && failCount == 0)
            {
                statusLabel.Text = $"Downloaded {successCount} file(s) successfully";
            }
            else if (successCount == 0 && failCount > 0)
            {
                statusLabel.Text = $"Download failed for all {failCount} file(s)";

                if (selectedFiles.Count > 1)
                {
                    MessageBox.Show($"Failed to download all {failCount} selected files. Check the console for details.",
                                  "Download Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                statusLabel.Text = $"Download completed: {successCount} success, {failCount} failed";

                if (selectedFiles.Count > 1)
                {
                    MessageBox.Show($"Download completed with mixed results:\n• {successCount} files downloaded successfully\n• {failCount} files failed",
                                  "Download Completed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        private async void UploadMenuItem_Click(object sender, EventArgs e)
        {
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Title = "Select files to upload";
                openFileDialog.Multiselect = true;
                openFileDialog.Filter = "All files (*.*)|*.*";

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    progressBar.Visible = true;
                    progressBar.Maximum = openFileDialog.FileNames.Length;
                    progressBar.Value = 0;

                    foreach (string localFile in openFileDialog.FileNames)
                    {
                        string fileName = Path.GetFileName(localFile);
                        string remotePath;

                        if (_isLinux)
                        {
                            remotePath = _currentPath.TrimEnd('/') + "/" + fileName;
                        }
                        else
                        {
                            remotePath = Path.Combine(_currentPath, fileName);
                        }

                        statusLabel.Text = $"Uploading {fileName}...";

                        try
                        {
                            await _server.UploadFileWithProgress(localFile, remotePath, progress =>
                            {
                                // Update progress if needed
                            });

                            statusLabel.Text = $"Uploaded {fileName}";
                        }
                        catch (Exception ex)
                        {
                            statusLabel.Text = $"Upload failed: {ex.Message}";
                            MessageBox.Show($"Failed to upload {fileName}: {ex.Message}", "Upload Error",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }

                        progressBar.Value++;
                        await Task.Delay(100);
                    }

                    progressBar.Visible = false;
                    await NavigateToPath(_currentPath); // Refresh directory
                    statusLabel.Text = $"Uploaded {openFileDialog.FileNames.Length} file(s)";
                }
            }
        }

        private async void NewFolderMenuItem_Click(object sender, EventArgs e)
        {
            await CreateNewFolder();
        }

        private async Task CreateNewFolder()
        {
            string promptText = _isLinux ? "Enter directory name:" : "Enter folder name:";
            string titleText = _isLinux ? "New Directory" : "New Folder";

            using (var inputDialog = new InputDialog(titleText, promptText))
            {
                if (inputDialog.ShowDialog() == DialogResult.OK)
                {
                    string folderName = inputDialog.InputValue.Trim();
                    if (string.IsNullOrEmpty(folderName))
                    {
                        MessageBox.Show($"{(_isLinux ? "Directory" : "Folder")} name cannot be empty.", "Invalid Name",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }

                    // Validate folder name based on OS
                    char[] invalidChars;
                    if (_isLinux)
                    {
                        invalidChars = new[] { '/', '\0' }; // Linux: only / and null are forbidden
                    }
                    else
                    {
                        invalidChars = Path.GetInvalidFileNameChars(); // Windows restrictions
                    }

                    if (folderName.Any(c => invalidChars.Contains(c)))
                    {
                        MessageBox.Show($"{(_isLinux ? "Directory" : "Folder")} name contains invalid characters.", "Invalid Name",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }

                    string command;
                    string fullPath;

                    if (_isLinux)
                    {
                        fullPath = Path.Combine(_currentPath, folderName).Replace('\\', '/');
                        command = $"mkdir \"{fullPath}\"";
                    }
                    else
                    {
                        fullPath = Path.Combine(_currentPath, folderName);
                        command = $"mkdir \"{fullPath}\"";
                    }

                    statusLabel.Text = $"Creating {(_isLinux ? "directory" : "folder")} {folderName}...";
                    _server.SendCommand(command);
                    await Task.Delay(1000);

                    await NavigateToPath(_currentPath);
                    statusLabel.Text = $"Created {(_isLinux ? "directory" : "folder")} {folderName}";
                }
            }
        }

        private async void DeleteMenuItem_Click(object sender, EventArgs e)
        {
            if (lvFiles.SelectedItems.Count == 0) return;

            var selectedItems = lvFiles.SelectedItems.Cast<ListViewItem>().ToList();
            string message = selectedItems.Count == 1
                ? $"Are you sure you want to delete '{((EnhancedFileItem)selectedItems[0].Tag).Name}'?"
                : $"Are you sure you want to delete {selectedItems.Count} selected items?";

            var result = MessageBox.Show(message, "Confirm Delete",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (result == DialogResult.Yes)
            {
                progressBar.Visible = true;
                progressBar.Maximum = selectedItems.Count;
                progressBar.Value = 0;

                foreach (ListViewItem item in selectedItems)
                {
                    var fileItem = (EnhancedFileItem)item.Tag;
                    statusLabel.Text = $"Deleting {fileItem.Name}...";

                    string command;
                    if (_isLinux)
                    {
                        if (fileItem.IsDirectory)
                        {
                            command = $"rm -rf \"{fileItem.FullPath}\""; // Recursive delete for directories
                        }
                        else
                        {
                            command = $"rm \"{fileItem.FullPath}\""; // Simple delete for files
                        }
                    }
                    else
                    {
                        // Windows logic (existing)
                        command = fileItem.IsDirectory
                            ? $"rmdir /S /Q \"{fileItem.FullPath}\""
                            : $"del /F /Q \"{fileItem.FullPath}\"";
                    }

                    _server.SendCommand(command);
                    progressBar.Value++;
                    await Task.Delay(300);
                }

                progressBar.Visible = false;
                await NavigateToPath(_currentPath);
                statusLabel.Text = "Delete operation completed";
            }
        }

        private void CopyPathMenuItem_Click(object sender, EventArgs e)
        {
            if (lvFiles.SelectedItems.Count > 0)
            {
                var fileItem = (EnhancedFileItem)lvFiles.SelectedItems[0].Tag;
                Clipboard.SetText(fileItem.FullPath);
                statusLabel.Text = $"Copied path: {fileItem.FullPath}";
            }
        }

        private void PropertiesMenuItem_Click(object sender, EventArgs e)
        {
            if (lvFiles.SelectedItems.Count > 0)
            {
                var fileItem = (EnhancedFileItem)lvFiles.SelectedItems[0].Tag;
                ShowFileProperties(fileItem);
            }
        }

        private void ShowFileProperties(EnhancedFileItem fileItem)
        {
            Form propertiesForm = new Form
            {
                Text = $"Properties - {fileItem.Name}",
                Size = new Size(400, 350),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            string properties = $"Name: {fileItem.Name}\n" +
                               $"Type: {(fileItem.IsDirectory ? "Folder" : GetFileType(fileItem.Name))}\n" +
                               $"Location: {Path.GetDirectoryName(fileItem.FullPath)}\n" +
                               $"Size: {(fileItem.IsDirectory ? "<DIR>" : FormatFileSizeFromString(fileItem.Size))}\n" +
                               $"Full Path: {fileItem.FullPath}";

            TextBox txtProperties = new TextBox
            {
                Location = new Point(20, 20),
                Size = new Size(340, 250),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Font = new Font("Consolas", 9),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Text = properties
            };

            Button btnClose = new Button
            {
                Text = "Close",
                Location = new Point(280, 280),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };
            btnClose.Click += (s, e) => propertiesForm.Close();

            propertiesForm.Controls.AddRange(new Control[] { txtProperties, btnClose });
            propertiesForm.ShowDialog();
        }

        private void LvFiles_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
            }
        }

        private async void LvFiles_DragDrop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);

                progressBar.Visible = true;
                progressBar.Maximum = files.Length;
                progressBar.Value = 0;

                foreach (string localFile in files)
                {
                    if (File.Exists(localFile))
                    {
                        string fileName = Path.GetFileName(localFile);
                        string remotePath;

                        if (_isLinux)
                        {
                            remotePath = _currentPath.TrimEnd('/') + "/" + fileName;
                        }
                        else
                        {
                            remotePath = Path.Combine(_currentPath, fileName);
                        }

                        statusLabel.Text = $"Uploading {fileName} (drag & drop)...";

                        try
                        {
                            await _server.UploadFileWithProgress(localFile, remotePath, progress => { });
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Failed to upload {fileName}: {ex.Message}", "Upload Error",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }

                        progressBar.Value++;
                        await Task.Delay(100);
                    }
                }

                progressBar.Visible = false;
                await NavigateToPath(_currentPath);
                statusLabel.Text = "Drag & drop upload completed";
            }
        }

        #endregion

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            contextMenuFiles?.Dispose();
            statusStrip?.Dispose();
            base.OnFormClosing(e);
        }
    }
}