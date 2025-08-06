using System.Drawing.Drawing2D;

namespace C2Framework
{
    public partial class NetworkTopologyViewer : UserControl
    {
        private List<BeaconNode> _beaconNodes = new List<BeaconNode>();
        private BeaconNode _serverNode;
        private Point _dragStart;
        private BeaconNode _draggedNode;
        private bool _isDragging = false;
        private System.Windows.Forms.Timer _animationTimer;
        private System.Windows.Forms.Timer _privilegeRefreshTimer;
        private float _animationTime = 0f;
        private Random _random = new Random();
        private Point _viewCenter;
        private float _zoomLevel = 0.7f;
        private ToolTip _tooltip;
        private Dictionary<BeaconNode, Vector2> _velocities = new Dictionary<BeaconNode, Vector2>();
        private List<Star> _stars = new List<Star>();
        private List<Particle> _particles = new List<Particle>();

        private List<NetworkPacket> _networkPackets = new List<NetworkPacket>();
        private Dictionary<BeaconNode, List<Vector2>> _nodeTrails = new Dictionary<BeaconNode, List<Vector2>>();
        private Dictionary<string, float> _nodeHealthMetrics = new Dictionary<string, float>();
        private bool _showGrid = false;
        private bool _showMetrics = false;
        private LayoutMode _layoutMode = LayoutMode.Circular;
        private List<Alert> _securityAlerts = new List<Alert>();
        private List<ConnectionPulse> _connectionPulses = new List<ConnectionPulse>();
        private Dictionary<BeaconNode, List<ScreenGlitch>> _nodeGlitches = new Dictionary<BeaconNode, List<ScreenGlitch>>();

        public event EventHandler<BeaconSelectedEventArgs> BeaconSelected;
        public event EventHandler<BeaconDoubleClickEventArgs> BeaconDoubleClicked;
        public event EventHandler PrivilegeRefreshRequested;

        public enum LayoutMode
        {
            Circular,
            Hierarchical,
            Force,
            Grid,
            Organic
        }

        private class Star
        {
            public Vector2 Position { get; set; }
            public Vector2 Velocity { get; set; }
            public float Size { get; set; }
            public float TwinklePhase { get; set; }
            public Color Color { get; set; } = Color.FromArgb(255, 80, 80);
            public float Brightness { get; set; } = 1.0f;
        }

        private class Particle
        {
            public Vector2 Position { get; set; }
            public Vector2 Velocity { get; set; }
            public float Life { get; set; }
            public float MaxLife { get; set; }
            public Color Color { get; set; }
            public float Size { get; set; }
            public ParticleType Type { get; set; }
        }

        private enum ParticleType
        {
            Spark,
            Smoke,
            Data,
            Energy
        }

        private class ConnectionPulse
        {
            public Vector2 StartPos { get; set; }
            public Vector2 EndPos { get; set; }
            public float Progress { get; set; }
            public Color Color { get; set; }
            public float Intensity { get; set; }
            public BeaconNode SourceNode { get; set; }
            public BeaconNode TargetNode { get; set; }
        }

        private class ScreenGlitch
        {
            public Rectangle Area { get; set; }
            public float Duration { get; set; }
            public float Timer { get; set; }
            public Color Color { get; set; }
        }

        private class Meteor
        {
            public Vector2 Position { get; set; }
            public Vector2 Velocity { get; set; }
            public float Timer { get; set; }
            public bool ShowText { get; set; }
            public List<Vector2> Trail { get; set; } = new List<Vector2>();
            public Color TrailColor { get; set; } = Color.FromArgb(255, 100, 0);
        }

        private class NetworkPacket
        {
            public Vector2 Position { get; set; }
            public Vector2 StartPos { get; set; }
            public Vector2 EndPos { get; set; }
            public float Progress { get; set; }
            public Color Color { get; set; }
            public PacketType Type { get; set; }
            public BeaconNode SourceNode { get; set; }
            public BeaconNode TargetNode { get; set; }
            public float LifeTime { get; set; }
            public float Size { get; set; } = 1.0f;
        }

        private class Alert
        {
            public string Message { get; set; }
            public AlertLevel Level { get; set; }
            public DateTime Timestamp { get; set; }
            public float FadeTimer { get; set; } = 8.0f;
            public BeaconNode AssociatedNode { get; set; }
            public float PulsePhase { get; set; }
        }

        public enum PacketType
        {
            Command,
            Data,
            Heartbeat,
            Error,
            Exploit
        }

        public enum AlertLevel
        {
            Info,
            Warning,
            Critical,
            Success
        }

        public NetworkTopologyViewer()
        {
            InitializeComponent();
            SetStyle(ControlStyles.AllPaintingInWmPaint |
                    ControlStyles.UserPaint |
                    ControlStyles.DoubleBuffer |
                    ControlStyles.ResizeRedraw, true);

            BackColor = Color.FromArgb(5, 0, 15);
            _viewCenter = new Point(Width / 2, Height / 2);

            _tooltip = new ToolTip();
            _tooltip.BackColor = Color.FromArgb(20, 20, 30);
            _tooltip.ForeColor = Color.FromArgb(0, 255, 150);
            _tooltip.SetToolTip(this, "");

            InitializeServerNode();
            InitializeStars();
            SetupAnimationTimer();
            SetupPrivilegeRefreshTimer();

            MouseDown += OnMouseDown;
            MouseMove += OnMouseMove;
            MouseUp += OnMouseUp;
            MouseWheel += OnMouseWheel;
            Resize += OnResize;
            KeyDown += OnKeyDown;

            SetStyle(ControlStyles.Selectable, true);
            TabStop = true;

            // Auto-focus when clicked
            Click += (s, e) => Focus();
        }

        protected override bool IsInputKey(Keys keyData)
        {
            // Allow all keys to be processed by this control
            return true;
        }
        private void OnKeyDown(object sender, KeyEventArgs e)
        {
            switch (e.KeyCode)
            {
                case Keys.G:
                    _showGrid = !_showGrid;
                    Invalidate();
                    break;

                case Keys.M:
                    _showMetrics = !_showMetrics;
                    Invalidate();
                    break;

                case Keys.L:
                    CycleLayoutMode();
                    break;

                case Keys.R:
                    ResetBeaconPositions();
                    break;

                case Keys.C:
                    CenterView();
                    break;

                case Keys.E:
                    // Trigger system glitch effect
                    if (_beaconNodes.Count > 0)
                    {
                        var randomNode = _beaconNodes[_random.Next(_beaconNodes.Count)];
                        CreateGlitchEffect(randomNode);
                    }
                    break;
            }
        }
        private void InitializeStars()
        {
            _stars.Clear();
            var starColors = new[] {
                Color.FromArgb(100, 200, 255),  // Ice blue
                Color.FromArgb(255, 100, 150),  // Pink
                Color.FromArgb(150, 255, 100),  // Green
                Color.FromArgb(255, 200, 100),  // Orange
                Color.FromArgb(200, 150, 255),  // Purple
                Color.FromArgb(255, 255, 200)   // Yellow
            };

            for (int i = 0; i < 500; i++)
            {
                _stars.Add(new Star
                {
                    Position = new Vector2(_random.Next(Width), _random.Next(Height)),
                    Velocity = new Vector2((float)(_random.NextDouble() - 0.5) * 0.5f, (float)(_random.NextDouble() - 0.5) * 0.5f),
                    Size = (float)(_random.NextDouble() * 4 + 0.5),
                    TwinklePhase = (float)(_random.NextDouble() * Math.PI * 2),
                    Color = starColors[_random.Next(starColors.Length)],
                    Brightness = (float)(_random.NextDouble() * 0.8 + 0.2)
                });
            }
        }


        private void InitializeComponent()
        {
            SuspendLayout();
            Name = "NetworkTopologyViewer";
            Size = new Size(1200, 800);
            Load += NetworkTopologyViewer_Load;
            ResumeLayout(false);
            TabStop = true;
        }

        private void InitializeServerNode()
        {
            _serverNode = new BeaconNode
            {
                Id = "SERVER",
                DisplayName = "SUN SERVER",
                Position = new Vector2(0, 0),
                NodeType = NodeType.Server,
                Status = NodeStatus.Active,
                Color = Color.FromArgb(0, 255, 150),
                IsFixed = false
            };
        }

        private void SetupAnimationTimer()
        {
            _animationTimer = new System.Windows.Forms.Timer();
            _animationTimer.Interval = 16; // ~60 FPS
            _animationTimer.Tick += AnimationTimer_Tick;
            _animationTimer.Start();
        }

        private void SetupPrivilegeRefreshTimer()
        {
            _privilegeRefreshTimer = new System.Windows.Forms.Timer();
            _privilegeRefreshTimer.Interval = 3000;
            _privilegeRefreshTimer.Tick += (s, e) => PrivilegeRefreshRequested?.Invoke(this, EventArgs.Empty);
            _privilegeRefreshTimer.Start();
        }


        private void CreateGlitchEffect(BeaconNode node)
        {
            if (!_nodeGlitches.ContainsKey(node))
                _nodeGlitches[node] = new List<ScreenGlitch>();

            var glitches = _nodeGlitches[node];
            var pos = GetScreenPosition(node.Position);
            var size = GetNodeSize(node);

            for (int i = 0; i < 3; i++)
            {
                glitches.Add(new ScreenGlitch
                {
                    Area = new Rectangle(pos.X - size, pos.Y - size, size * 2, size * 2),
                    Duration = 0.5f + (float)_random.NextDouble() * 0.5f,
                    Timer = 0f,
                    Color = Color.FromArgb(255, _random.Next(50, 255), 0, _random.Next(50, 255))
                });
            }
        }

        private void CycleLayoutMode()
        {
            _layoutMode = (LayoutMode)(((int)_layoutMode + 1) % Enum.GetValues(typeof(LayoutMode)).Length);
            ApplyLayout();
            Invalidate();
        }

        private void ApplyLayout()
        {
            if (_beaconNodes.Count == 0) return;

            switch (_layoutMode)
            {
                case LayoutMode.Circular:
                    ApplyCircularLayout();
                    break;
                case LayoutMode.Hierarchical:
                    ApplyHierarchicalLayout();
                    break;
                case LayoutMode.Grid:
                    ApplyGridLayout();
                    break;
                case LayoutMode.Organic:
                    ApplyOrganicLayout();
                    break;
                case LayoutMode.Force:
                    // Handled by physics
                    break;
            }
        }

        private void ApplyCircularLayout()
        {
            var levels = new Dictionary<int, List<BeaconNode>>();

            foreach (var node in _beaconNodes)
            {
                var level = GetPrivilegeLevel(node);
                if (!levels.ContainsKey(level))
                    levels[level] = new List<BeaconNode>();
                levels[level].Add(node);
            }

            foreach (var kvp in levels)
            {
                var level = kvp.Key;
                var nodes = kvp.Value;
                var radius = 100f + (level * 60f);

                for (int i = 0; i < nodes.Count; i++)
                {
                    var angle = (float)(i * 2 * Math.PI / nodes.Count);
                    nodes[i].Position = new Vector2(
                        _serverNode.Position.X + (float)(Math.Cos(angle) * radius),
                        _serverNode.Position.Y + (float)(Math.Sin(angle) * radius)
                    );
                }
            }
        }

        private void ApplyHierarchicalLayout()
        {
            var levels = new Dictionary<int, List<BeaconNode>>();

            foreach (var node in _beaconNodes)
            {
                var level = GetPrivilegeLevel(node);
                if (!levels.ContainsKey(level))
                    levels[level] = new List<BeaconNode>();
                levels[level].Add(node);
            }

            var yOffset = -200f;
            foreach (var kvp in levels.OrderByDescending(x => x.Key))
            {
                var nodesInLevel = kvp.Value;
                var xSpacing = Math.Min(150f, 600f / Math.Max(1, nodesInLevel.Count - 1));
                var startX = -(nodesInLevel.Count - 1) * xSpacing / 2;

                for (int i = 0; i < nodesInLevel.Count; i++)
                {
                    nodesInLevel[i].Position = new Vector2(
                        _serverNode.Position.X + startX + (i * xSpacing),
                        _serverNode.Position.Y + yOffset
                    );
                }
                yOffset += 120f;
            }
        }

        private void ApplyGridLayout()
        {
            var cols = (int)Math.Ceiling(Math.Sqrt(_beaconNodes.Count));
            var spacing = 100f;

            for (int i = 0; i < _beaconNodes.Count; i++)
            {
                var row = i / cols;
                var col = i % cols;
                var node = _beaconNodes[i];

                node.Position = new Vector2(
                    _serverNode.Position.X + (col - cols / 2f) * spacing,
                    _serverNode.Position.Y + (row * spacing) + 150f
                );
            }
        }

        private void ApplyOrganicLayout()
        {
            var groups = _beaconNodes.GroupBy(n => n.NodeType).ToList();
            var angleOffset = 0f;

            foreach (var group in groups)
            {
                var nodes = group.ToList();
                var groupRadius = 80f + (nodes.Count * 8f);
                var baseAngle = angleOffset;

                for (int i = 0; i < nodes.Count; i++)
                {
                    var angle = baseAngle + (float)(i * 2 * Math.PI / nodes.Count);
                    var jitter = (float)(_random.NextDouble() - 0.5) * 30f;

                    nodes[i].Position = new Vector2(
                        _serverNode.Position.X + (float)(Math.Cos(angle) * (groupRadius + jitter)),
                        _serverNode.Position.Y + (float)(Math.Sin(angle) * (groupRadius + jitter))
                    );
                }

                angleOffset += (float)(Math.PI / groups.Count);
            }
        }

        private int GetPrivilegeLevel(BeaconNode node)
        {
            return node.NodeType switch
            {
                NodeType.SystemLevel => 3,
                NodeType.Administrator => 2,
                NodeType.DomainUser => 1,
                NodeType.StandardUser => 0,
                _ => 0
            };
        }

        private void AnimationTimer_Tick(object sender, EventArgs e)
        {
            _animationTime += 0.016f;
            if (_animationTime > Math.PI * 2) _animationTime = 0f;

            UpdateNodePhysics();
            UpdateStars();
            UpdateParticles();
            UpdateNetworkPackets();
            UpdateConnectionPulses();
            UpdateNodeTrails();
            UpdateHealthMetrics();
            UpdateAlerts();
            UpdateGlitchEffects();

            // Spawn effects with much lower frequency
            if (_random.NextDouble() < 0.03 && _beaconNodes.Count > 0)
            {
                SpawnNetworkPacket();
            }

            if (_random.NextDouble() < 0.015)
            {
                SpawnConnectionPulse();
            }

            if (_random.NextDouble() < 0.008)
            {
                SpawnParticles();
            }

            Invalidate();
        }

        private void SpawnParticles()
        {
            var activeNodes = _beaconNodes.Where(n => n.Status == NodeStatus.Active).ToList();
            if (activeNodes.Count == 0) return;

            var node = activeNodes[_random.Next(activeNodes.Count)];

            for (int i = 0; i < 3; i++)
            {
                _particles.Add(new Particle
                {
                    Position = node.Position,
                    Velocity = new Vector2(
                        (float)(_random.NextDouble() - 0.5) * 2f,
                        (float)(_random.NextDouble() - 0.5) * 2f
                    ),
                    Life = 2.0f,
                    MaxLife = 2.0f,
                    Color = node.Color,
                    Size = (float)(_random.NextDouble() * 3 + 1),
                    Type = (ParticleType)_random.Next(4)
                });
            }
        }

        private void UpdateParticles()
        {
            for (int i = _particles.Count - 1; i >= 0; i--)
            {
                var particle = _particles[i];
                particle.Life -= 0.016f;
                particle.Position = Vector2.Add(particle.Position, Vector2.Multiply(particle.Velocity, 0.016f));
                particle.Velocity = Vector2.Multiply(particle.Velocity, 0.98f);

                if (particle.Life <= 0)
                {
                    _particles.RemoveAt(i);
                }
            }
        }

        private void SpawnConnectionPulse()
        {
            var activeNodes = _beaconNodes.Where(n => n.Status == NodeStatus.Active).ToList();
            if (activeNodes.Count == 0) return;

            var sourceNode = _random.NextDouble() < 0.7 ? _serverNode : activeNodes[_random.Next(activeNodes.Count)];
            var targetNode = sourceNode == _serverNode ? activeNodes[_random.Next(activeNodes.Count)] : _serverNode;

            _connectionPulses.Add(new ConnectionPulse
            {
                StartPos = sourceNode.Position,
                EndPos = targetNode.Position,
                Progress = 0f,
                Color = GetConnectionColor(targetNode),
                Intensity = 1.0f,
                SourceNode = sourceNode,
                TargetNode = targetNode
            });
        }

        private void UpdateConnectionPulses()
        {
            for (int i = _connectionPulses.Count - 1; i >= 0; i--)
            {
                var pulse = _connectionPulses[i];
                pulse.Progress += 0.012f;
                pulse.Intensity = Math.Max(0, pulse.Intensity - 0.008f);

                if (pulse.Progress >= 1.0f || pulse.Intensity <= 0)
                {
                    _connectionPulses.RemoveAt(i);
                }
            }
        }

        private void UpdateGlitchEffects()
        {
            foreach (var kvp in _nodeGlitches.ToList())
            {
                var glitches = kvp.Value;
                for (int i = glitches.Count - 1; i >= 0; i--)
                {
                    glitches[i].Timer += 0.016f;
                    if (glitches[i].Timer >= glitches[i].Duration)
                    {
                        glitches.RemoveAt(i);
                    }
                }

                if (glitches.Count == 0)
                {
                    _nodeGlitches.Remove(kvp.Key);
                }
            }
        }

        private void SpawnNetworkPacket()
        {
            var activeNodes = _beaconNodes.Where(n => n.Status == NodeStatus.Active).ToList();
            if (activeNodes.Count == 0) return;

            var sourceNode = _random.NextDouble() < 0.7 ? _serverNode : activeNodes[_random.Next(activeNodes.Count)];
            var targetNode = sourceNode == _serverNode ? activeNodes[_random.Next(activeNodes.Count)] : _serverNode;

            var packetTypes = Enum.GetValues(typeof(PacketType)).Cast<PacketType>().ToArray();
            var packetType = packetTypes[_random.Next(packetTypes.Length)];

            var packet = new NetworkPacket
            {
                StartPos = sourceNode.Position,
                EndPos = targetNode.Position,
                Position = sourceNode.Position,
                Progress = 0f,
                Type = packetType,
                Color = GetPacketColor(packetType),
                SourceNode = sourceNode,
                TargetNode = targetNode,
                LifeTime = 8.0f + (float)_random.NextDouble() * 4.0f,
                Size = packetType == PacketType.Data ? 1.2f : 0.8f
            };

            _networkPackets.Add(packet);
        }

        private Color GetPacketColor(PacketType type)
        {
            return type switch
            {
                PacketType.Command => Color.FromArgb(255, 100, 100),
                PacketType.Data => Color.FromArgb(100, 255, 100),
                PacketType.Heartbeat => Color.FromArgb(100, 150, 255),
                PacketType.Error => Color.FromArgb(255, 200, 100),
                PacketType.Exploit => Color.FromArgb(255, 50, 200),
                _ => Color.White
            };
        }

        private void UpdateNetworkPackets()
        {
            for (int i = _networkPackets.Count - 1; i >= 0; i--)
            {
                var packet = _networkPackets[i];
                packet.Progress += 0.008f;
                packet.LifeTime -= 0.016f;

                if (packet.Progress >= 1.0f || packet.LifeTime <= 0)
                {
                    _networkPackets.RemoveAt(i);
                    continue;
                }

                var t = packet.Progress;
                var smoothT = t * t * (3.0f - 2.0f * t);

                packet.Position = Vector2.Add(
                    Vector2.Multiply(packet.StartPos, 1 - smoothT),
                    Vector2.Multiply(packet.EndPos, smoothT)
                );

                var midPoint = Vector2.Multiply(Vector2.Add(packet.StartPos, packet.EndPos), 0.5f);
                var perpendicular = new Vector2(-(packet.EndPos.Y - packet.StartPos.Y), packet.EndPos.X - packet.StartPos.X);
                perpendicular = Vector2.Multiply(Vector2.Normalize(perpendicular), 15f * (float)Math.Sin(t * Math.PI)); // Reduced from 25f to 15f
                packet.Position = Vector2.Add(packet.Position, perpendicular);
            }
        }

        private void UpdateNodeTrails()
        {
            foreach (var node in _beaconNodes)
            {
                if (!_nodeTrails.ContainsKey(node))
                    _nodeTrails[node] = new List<Vector2>();

                var trail = _nodeTrails[node];
                if (_layoutMode == LayoutMode.Force)
                {
                    trail.Add(node.Position);
                    if (trail.Count > 15)
                        trail.RemoveAt(0);
                }
                else
                {
                    trail.Clear();
                }
            }
        }

        private void UpdateHealthMetrics()
        {
            foreach (var node in _beaconNodes)
            {
                if (!_nodeHealthMetrics.ContainsKey(node.Id))
                    _nodeHealthMetrics[node.Id] = 1.0f;

                var healthChange = (float)(_random.NextDouble() - 0.5) * 0.015f;
                _nodeHealthMetrics[node.Id] = Math.Max(0.1f, Math.Min(1.0f, _nodeHealthMetrics[node.Id] + healthChange));

                if (_nodeHealthMetrics[node.Id] < 0.3f && _random.NextDouble() < 0.005f)
                {
                    CreateGlitchEffect(node);
                }
            }
        }

        private void UpdateAlerts()
        {
            for (int i = _securityAlerts.Count - 1; i >= 0; i--)
            {
                _securityAlerts[i].FadeTimer -= 0.016f;
                _securityAlerts[i].PulsePhase += 0.1f;
                if (_securityAlerts[i].FadeTimer <= 0)
                    _securityAlerts.RemoveAt(i);
            }
        }



        public void UpdateBeacons(List<ClientInfo> clients)
        {
            var existingIds = _beaconNodes.Select(n => n.Id).ToHashSet();
            var currentIds = clients.Select(c => c.ClientId).ToHashSet();

            var nodesToRemove = _beaconNodes.Where(n => !currentIds.Contains(n.Id)).ToList();
            foreach (var node in nodesToRemove)
            {
                _beaconNodes.Remove(node);
                _velocities.Remove(node);
                _nodeTrails.Remove(node);
                _nodeHealthMetrics.Remove(node.Id);
                _nodeGlitches.Remove(node);
            }

            foreach (var client in clients)
            {
                if (!existingIds.Contains(client.ClientId))
                {
                    AddBeacon(client);
                }
                else
                {
                    var node = _beaconNodes.FirstOrDefault(n => n.Id == client.ClientId);
                    if (node != null)
                    {
                        UpdateBeaconStatus(node, client);
                    }
                }
            }

            Invalidate();
        }

        private void AddBeacon(ClientInfo client)
        {
            var angle = _random.NextDouble() * Math.PI * 2;
            var radius = 120 + _random.NextDouble() * 60;

            var node = new BeaconNode
            {
                Id = client.ClientId,
                DisplayName = !string.IsNullOrEmpty(client.ComputerName) ? client.ComputerName : client.ClientId,
                Position = new Vector2(
                    _serverNode.Position.X + (float)(Math.Cos(angle) * radius),
                    _serverNode.Position.Y + (float)(Math.Sin(angle) * radius)
                ),
                NodeType = DetermineNodeType(client),
                Status = client.IsConnected ? NodeStatus.Active : NodeStatus.Inactive,
                ClientInfo = client,
                Color = GetNodeColor(client),
                IsFixed = false
            };

            _beaconNodes.Add(node);
            _velocities[node] = new Vector2();
            _nodeHealthMetrics[node.Id] = 1.0f;

        }

        private void UpdateBeaconStatus(BeaconNode node, ClientInfo client)
        {
            var wasActive = node.Status == NodeStatus.Active;
            node.Status = client.IsConnected ? NodeStatus.Active : NodeStatus.Inactive;
            node.ClientInfo = client;
            node.Color = GetNodeColor(client);
            node.DisplayName = !string.IsNullOrEmpty(client.ComputerName) ? client.ComputerName : client.ClientId;
            node.NodeType = DetermineNodeType(client);

            if (!wasActive && node.Status == NodeStatus.Active)
            {
            }
            else if (wasActive && node.Status != NodeStatus.Active)
            {
            }
        }

        private NodeType DetermineNodeType(ClientInfo client)
        {
            var userName = client.UserName?.ToLower() ?? "";
            if (userName.Contains("system") || userName.Contains("nt authority") || userName.EndsWith("$"))
                return NodeType.SystemLevel;
            if (client.IsAdmin || userName.Contains("admin") || userName.Contains("administrator"))
                return NodeType.Administrator;
            if (client.IsDomainJoined || userName.Contains("\\") && !userName.Contains("nt authority"))
                return NodeType.DomainUser;
            return NodeType.StandardUser;
        }

        private Color GetNodeColor(ClientInfo client)
        {
            if (client.UserName?.Contains("SYSTEM") == true || client.UserName?.Contains("NT AUTHORITY") == true)
                return Color.FromArgb(255, 100, 100);
            else if (client.IsAdmin)
                return Color.FromArgb(255, 150, 100);
            else if (client.IsDomainJoined)
                return Color.FromArgb(150, 100, 255);
            else
                return Color.FromArgb(100, 255, 150);
        }

        public void SetActiveBeacon(string beaconId)
        {
            foreach (var node in _beaconNodes)
            {
                node.IsSelected = node.Id == beaconId;
            }
            Invalidate();
        }

        public void SimulateSecurityEvent(string nodeId, string eventType)
        {
            var node = _beaconNodes.FirstOrDefault(n => n.Id == nodeId);
            if (node != null)
            {
                var alertLevel = eventType.ToLower() switch
                {
                    "breach" => AlertLevel.Critical,
                    "exploit" => AlertLevel.Critical,
                    "suspicious" => AlertLevel.Warning,
                    "success" => AlertLevel.Success,
                    _ => AlertLevel.Info
                };


                if (alertLevel == AlertLevel.Critical)
                {
                    CreateGlitchEffect(node);
                    node.Color = Color.FromArgb(255, 50, 50);
                }
            }
        }

        private void UpdateNodePhysics()
        {
            if (_layoutMode != LayoutMode.Force) return;

            const float damping = 0.85f;
            const float springStrength = 0.15f;
            const float repulsionStrength = 800f;
            const float maxVelocity = 4.0f;
            const float maxDistance = 300f;

            foreach (var node in _beaconNodes)
            {
                if (node == _draggedNode && _isDragging) continue;
                if (node.IsFixed) continue;

                Vector2 force = new Vector2();

                var toServer = Vector2.Subtract(_serverNode.Position, node.Position);
                var distanceToServer = toServer.Length();

                if (distanceToServer > 0)
                {
                    var desiredDistance = 140f + (GetPrivilegeLevel(node) * 40f);

                    if (distanceToServer > maxDistance)
                    {
                        var pullBackForce = (distanceToServer - maxDistance) * springStrength * 2.0f;
                        force = Vector2.Add(force, Vector2.Multiply(Vector2.Normalize(toServer), pullBackForce));
                    }
                    else
                    {
                        var springForce = (distanceToServer - desiredDistance) * springStrength;
                        force = Vector2.Add(force, Vector2.Multiply(Vector2.Normalize(toServer), springForce));
                    }
                }

                foreach (var otherNode in _beaconNodes)
                {
                    if (otherNode == node) continue;

                    var toOther = Vector2.Subtract(node.Position, otherNode.Position);
                    var distance = toOther.Length();
                    if (distance > 0 && distance < 120f)
                    {
                        var repulsion = repulsionStrength / Math.Max(distance * distance, 1f);
                        force = Vector2.Add(force, Vector2.Multiply(Vector2.Normalize(toOther), repulsion));
                    }
                }

                if (!_velocities.ContainsKey(node))
                    _velocities[node] = new Vector2();

                _velocities[node] = Vector2.Add(_velocities[node], force);
                _velocities[node] = Vector2.Multiply(_velocities[node], damping);

                var velocityLength = _velocities[node].Length();
                if (velocityLength > maxVelocity)
                {
                    _velocities[node] = Vector2.Multiply(Vector2.Normalize(_velocities[node]), maxVelocity);
                }

                node.Position = Vector2.Add(node.Position, Vector2.Multiply(_velocities[node], 0.016f));

                var finalDistanceToServer = Vector2.Distance(node.Position, _serverNode.Position);
                if (finalDistanceToServer > maxDistance)
                {
                    var direction = Vector2.Normalize(Vector2.Subtract(node.Position, _serverNode.Position));
                    node.Position = Vector2.Add(_serverNode.Position, Vector2.Multiply(direction, maxDistance * 0.9f));
                    _velocities[node] = Vector2.Multiply(_velocities[node], 0.3f);
                }
            }
        }

        private void UpdateStars()
        {
            foreach (var star in _stars)
            {
                star.Position = Vector2.Add(star.Position, star.Velocity);
                star.TwinklePhase += 0.05f + (star.Size * 0.02f);

                if (star.Position.X < 0) star.Position = new Vector2(star.Position.X + Width, star.Position.Y);
                if (star.Position.X > Width) star.Position = new Vector2(star.Position.X - Width, star.Position.Y);
                if (star.Position.Y < 0) star.Position = new Vector2(star.Position.X, star.Position.Y + Height);
                if (star.Position.Y > Height) star.Position = new Vector2(star.Position.X, star.Position.Y - Height);
            }
        }



        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            g.CompositingQuality = CompositingQuality.HighQuality;

            DrawBackground(g);
            DrawGrid(g);
            DrawConnections(g);
            DrawConnectionPulses(g);
            DrawNetworkPackets(g);
            DrawParticles(g);
            DrawNodeTrails(g);
            DrawServer(g);
            DrawBeacons(g);
            DrawGlitchEffects(g);
            DrawUI(g);
        }

        private void DrawBackground(Graphics g)
        {
            using (var brush = new LinearGradientBrush(
                new Point(0, 0),
                new Point(Width, Height),
                Color.FromArgb(10, 5, 25),
                Color.FromArgb(5, 15, 35)))
            {
                g.FillRectangle(brush, 0, 0, Width, Height);
            }

            foreach (var star in _stars)
            {
                var twinkle = (float)(Math.Sin(_animationTime * 3 + star.TwinklePhase) * 0.6 + 0.4);
                var alpha = Math.Max(30, Math.Min(255, (int)(star.Brightness * 200 * twinkle)));

                using (var brush = new SolidBrush(Color.FromArgb(alpha, star.Color)))
                {
                    var size = star.Size * (0.5f + twinkle * 0.5f);
                    g.FillEllipse(brush, star.Position.X - size / 2, star.Position.Y - size / 2, size, size);

                    if (star.Size > 2.5f)
                    {
                        using (var glowBrush = new SolidBrush(Color.FromArgb(alpha / 4, star.Color)))
                        {
                            var glowSize = size * 2;
                            g.FillEllipse(glowBrush, star.Position.X - glowSize / 2, star.Position.Y - glowSize / 2, glowSize, glowSize);
                        }
                    }
                }
            }

            DrawNebula(g);
        }

        private void DrawNebula(Graphics g)
        {
            var centerX = Width / 2f;
            var centerY = Height / 2f;

            using (var path = new GraphicsPath())
            {
                path.AddEllipse(centerX - 200, centerY - 150, 400, 300);
                using (var pathBrush = new PathGradientBrush(path))
                {
                    pathBrush.CenterColor = Color.FromArgb(15, 50, 100, 150);
                    pathBrush.SurroundColors = new[] { Color.FromArgb(0, 50, 100, 150) };
                    g.FillPath(pathBrush, path);
                }
            }
        }



        private void DrawGrid(Graphics g)
        {
            if (!_showGrid) return;

            using (var pen = new Pen(Color.FromArgb(25, 0, 255, 150), 1f))
            {
                pen.DashStyle = DashStyle.Dot;

                var spacing = 60 * _zoomLevel;
                var centerX = _viewCenter.X;
                var centerY = _viewCenter.Y;

                for (float x = centerX % spacing; x < Width; x += spacing)
                {
                    g.DrawLine(pen, x, 0, x, Height);
                }

                for (float y = centerY % spacing; y < Height; y += spacing)
                {
                    g.DrawLine(pen, 0, y, Width, y);
                }
            }
        }

        private void DrawConnections(Graphics g)
        {
            var serverPos = GetScreenPosition(_serverNode.Position);

            foreach (var node in _beaconNodes)
            {
                if (node.Status == NodeStatus.Inactive) continue;

                var nodePos = GetScreenPosition(node.Position);
                DrawConnection(g, serverPos, nodePos, node);
            }
        }

        private void DrawConnection(Graphics g, Point start, Point end, BeaconNode node)
        {
            var connectionColor = GetConnectionColor(node);
            var pulse = (float)(Math.Sin(_animationTime * 4 + node.Id.GetHashCode()) * 0.3 + 0.7);
            var alpha = Math.Max(50, Math.Min(200, (int)(150 * pulse)));

            using (var pen = new Pen(Color.FromArgb(alpha / 2, connectionColor), 2f))
            {
                pen.DashStyle = DashStyle.Custom;
                pen.DashPattern = new float[] { 8f, 4f };
                g.DrawLine(pen, start, end);
            }

            DrawDataFlow(g, start, end, node);
        }

        private void DrawDataFlow(Graphics g, Point start, Point end, BeaconNode node)
        {
            for (int i = 0; i < 4; i++)
            {
                var offset = i * 0.25f;
                var progress = (float)(((_animationTime * 1.5 + offset + node.Id.GetHashCode() % 100 / 100.0) % 1.0));
                var flowPoint = new Point(
                    (int)(start.X + (end.X - start.X) * progress),
                    (int)(start.Y + (end.Y - start.Y) * progress));

                var particleColor = GetConnectionColor(node);
                var flicker = (float)(Math.Sin(_animationTime * 8 + i) * 0.3 + 0.7);
                var alpha = Math.Max(60, Math.Min(180, (int)(120 * flicker)));
                var size = 2 + i / 2;

                if (size > 0)
                {
                    using (var brush = new SolidBrush(Color.FromArgb(alpha, particleColor)))
                    {
                        g.FillEllipse(brush, flowPoint.X - size / 2, flowPoint.Y - size / 2, size, size);
                    }

                    if (size > 1)
                    {
                        using (var glowBrush = new SolidBrush(Color.FromArgb(alpha / 4, particleColor)))
                        {
                            var glowSize = size + 2;
                            g.FillEllipse(glowBrush, flowPoint.X - glowSize / 2, flowPoint.Y - glowSize / 2, glowSize, glowSize);
                        }
                    }
                }
            }
        }

        private void DrawConnectionPulses(Graphics g)
        {
            foreach (var pulse in _connectionPulses)
            {
                var startPos = GetScreenPosition(pulse.StartPos);
                var endPos = GetScreenPosition(pulse.EndPos);
                var currentPos = new Point(
                    (int)(startPos.X + (endPos.X - startPos.X) * pulse.Progress),
                    (int)(startPos.Y + (endPos.Y - startPos.Y) * pulse.Progress)
                );

                var alpha = Math.Max(30, Math.Min(150, (int)(pulse.Intensity * 150)));
                using (var brush = new SolidBrush(Color.FromArgb(alpha, pulse.Color)))
                {
                    var size = (int)(6 * pulse.Intensity);
                    g.FillEllipse(brush, currentPos.X - size / 2, currentPos.Y - size / 2, size, size);
                }


                using (var glowBrush = new SolidBrush(Color.FromArgb(alpha / 5, pulse.Color)))
                {
                    var glowSize = (int)(10 * pulse.Intensity);
                    g.FillEllipse(glowBrush, currentPos.X - glowSize / 2, currentPos.Y - glowSize / 2, glowSize, glowSize);
                }
            }
        }

        private Color GetConnectionColor(BeaconNode node)
        {
            if (node.ClientInfo?.IsEncrypted == true)
                return Color.FromArgb(0, 255, 150);

            return node.NodeType switch
            {
                NodeType.SystemLevel => Color.FromArgb(255, 100, 100),
                NodeType.Administrator => Color.FromArgb(255, 150, 100),
                NodeType.DomainUser => Color.FromArgb(150, 100, 255),
                _ => Color.FromArgb(100, 200, 255)
            };
        }

        private void DrawNetworkPackets(Graphics g)
        {
            foreach (var packet in _networkPackets)
            {
                var pos = GetScreenPosition(packet.Position);
                var alpha = Math.Max(40, Math.Min(200, (int)(200 * (packet.LifeTime / 12.0f))));
                var color = Color.FromArgb(alpha, packet.Color);
                var size = (int)(5 * packet.Size);

                using (var brush = new SolidBrush(color))
                {
                    if (packet.Type == PacketType.Command)
                    {
                        g.FillRectangle(brush, pos.X - size / 2, pos.Y - size / 2, size, size);
                    }
                    else if (packet.Type == PacketType.Exploit)
                    {
                        DrawTriangle(g, brush, pos, size);
                    }
                    else
                    {
                        g.FillEllipse(brush, pos.X - size / 2, pos.Y - size / 2, size, size);
                    }
                }


                using (var glowBrush = new SolidBrush(Color.FromArgb(alpha / 6, packet.Color)))
                {
                    var glowSize = size + 3;
                    g.FillEllipse(glowBrush, pos.X - glowSize / 2, pos.Y - glowSize / 2, glowSize, glowSize);
                }
            }
        }

        private void DrawTriangle(Graphics g, Brush brush, Point center, int size)
        {
            var points = new Point[]
            {
                new Point(center.X, center.Y - size / 2),
                new Point(center.X - size / 2, center.Y + size / 2),
                new Point(center.X + size / 2, center.Y + size / 2)
            };
            g.FillPolygon(brush, points);
        }

        private void DrawParticles(Graphics g)
        {
            foreach (var particle in _particles)
            {
                var pos = GetScreenPosition(particle.Position);
                var alpha = Math.Max(20, Math.Min(255, (int)(255 * (particle.Life / particle.MaxLife))));
                var color = Color.FromArgb(alpha, particle.Color);
                var size = particle.Size * (particle.Life / particle.MaxLife);

                using (var brush = new SolidBrush(color))
                {
                    switch (particle.Type)
                    {
                        case ParticleType.Spark:
                            g.FillEllipse(brush, pos.X - size / 2, pos.Y - size / 2, size, size);
                            break;
                        case ParticleType.Smoke:
                            using (var smokeBrush = new SolidBrush(Color.FromArgb(alpha / 3, 150, 150, 150)))
                            {
                                g.FillEllipse(smokeBrush, pos.X - size, pos.Y - size, size * 2, size * 2);
                            }
                            break;
                        case ParticleType.Data:
                            g.FillRectangle(brush, pos.X - size / 2, pos.Y - size / 2, size, size / 2);
                            break;
                        case ParticleType.Energy:
                            using (var pen = new Pen(color, 2f))
                            {
                                g.DrawLine(pen, pos.X - size, pos.Y, pos.X + size, pos.Y);
                                g.DrawLine(pen, pos.X, pos.Y - size, pos.X, pos.Y + size);
                            }
                            break;
                    }
                }
            }
        }

        private void DrawNodeTrails(Graphics g)
        {
            foreach (var kvp in _nodeTrails)
            {
                var trail = kvp.Value;
                if (trail.Count < 2) continue;

                for (int i = 1; i < trail.Count; i++)
                {
                    var alpha = (int)(60 * (i / (float)trail.Count));
                    using (var pen = new Pen(Color.FromArgb(alpha, 100, 255, 200), 2f))
                    {
                        var start = GetScreenPosition(trail[i - 1]);
                        var end = GetScreenPosition(trail[i]);
                        g.DrawLine(pen, start, end);
                    }
                }
            }
        }

        private void DrawServer(Graphics g)
        {
            var pos = GetScreenPosition(_serverNode.Position);
            var size = GetNodeSize(_serverNode);
            var serverRect = new Rectangle(pos.X - size / 2, pos.Y - size / 2, size, size);

            var pulse = (float)(Math.Sin(_animationTime * 4) * 0.3 + 0.7);
            var glowSize = (int)(size * (1.0f + pulse * 0.5f));
            var glowAlpha = Math.Max(50, Math.Min(150, (int)(100 * pulse)));

            // Multiple glow layers
            for (int i = 3; i >= 1; i--)
            {
                var layerSize = glowSize + (i * 15);
                var layerAlpha = glowAlpha / (i + 1);
                using (var glowBrush = new SolidBrush(Color.FromArgb(layerAlpha, 0, 255, 150)))
                {
                    g.FillEllipse(glowBrush, pos.X - layerSize / 2, pos.Y - layerSize / 2, layerSize, layerSize);
                }
            }

            // Main server body with gradient
            using (var brush = new LinearGradientBrush(serverRect,
                Color.FromArgb(50, 200, 255), Color.FromArgb(0, 100, 150), 45f))
            {
                g.FillEllipse(brush, serverRect);
            }

            // Neural network pattern
            DrawNeuralPattern(g, pos, size / 2);

            // Server border
            using (var pen = new Pen(Color.FromArgb(255, 0, 255, 150), 3f))
            {
                g.DrawEllipse(pen, serverRect);
            }

            // Central core
            var coreSize = size / 3;
            var coreRect = new Rectangle(pos.X - coreSize / 2, pos.Y - coreSize / 2, coreSize, coreSize);
            using (var coreBrush = new SolidBrush(Color.FromArgb(255, 255, 255)))
            {
                g.FillEllipse(coreBrush, coreRect);
            }

            DrawNodeLabel(g, _serverNode, pos);
        }

        private void DrawNeuralPattern(Graphics g, Point center, int radius)
        {
            var nodeCount = 8;
            var nodes = new Point[nodeCount];

            for (int i = 0; i < nodeCount; i++)
            {
                var angle = (float)(i * 2 * Math.PI / nodeCount);
                nodes[i] = new Point(
                    center.X + (int)(Math.Cos(angle) * radius * 0.6),
                    center.Y + (int)(Math.Sin(angle) * radius * 0.6)
                );
            }

            // Draw connections between nodes
            using (var pen = new Pen(Color.FromArgb(100, 0, 255, 200), 1.5f))
            {
                for (int i = 0; i < nodeCount; i++)
                {
                    for (int j = i + 1; j < nodeCount; j++)
                    {
                        if (_random.NextDouble() < 0.4) // Random connections
                        {
                            g.DrawLine(pen, nodes[i], nodes[j]);
                        }
                    }
                }
            }

            // Draw nodes
            using (var brush = new SolidBrush(Color.FromArgb(200, 0, 255, 200)))
            {
                foreach (var node in nodes)
                {
                    g.FillEllipse(brush, node.X - 2, node.Y - 2, 4, 4);
                }
            }
        }

        private void DrawBeacons(Graphics g)
        {
            foreach (var node in _beaconNodes)
            {
                DrawComputerNode(g, node);
            }
        }

        private void DrawComputerNode(Graphics g, BeaconNode node)
        {
            var pos = GetScreenPosition(node.Position);
            var baseSize = GetNodeSize(node);

            if (node.Status == NodeStatus.Active)
            {
                var pulse = (float)(Math.Sin(_animationTime * 5 + node.Id.GetHashCode()) * 0.15 + 0.85);
                baseSize = (int)(baseSize * pulse);
            }

            // Draw node based on OS type
            if (node.ClientInfo?.IsLinux == true)
            {
                DrawEnhancedLinuxComputer(g, node, pos, baseSize);
            }
            else
            {
                DrawEnhancedWindowsComputer(g, node, pos, baseSize);
            }

            DrawEnhancedStatusIndicator(g, node, pos, baseSize);
            DrawEnhancedPrivilegeIndicator(g, node, pos, baseSize);
            DrawEncryptionIndicator(g, node, pos, baseSize);

            if (node.IsSelected)
            {
                DrawSelectionHighlight(g, pos, baseSize);
            }

            DrawNodeLabel(g, node, pos);
        }

        private void DrawEnhancedWindowsComputer(Graphics g, BeaconNode node, Point pos, int size)
        {
            bool isHighPrivilege = node.NodeType == NodeType.Administrator || node.NodeType == NodeType.SystemLevel;
            var monitorRect = new Rectangle(pos.X - size / 2, pos.Y - size / 2, size, (int)(size * 0.7));

            // Enhanced glow effects
            if (node.Status == NodeStatus.Active)
            {
                var pulse = (float)(Math.Sin(_animationTime * 8) * 0.4 + 0.6);
                var glowAlpha = Math.Max(40, Math.Min(120, (int)(100 * pulse)));
                var glowColor = isHighPrivilege ? Color.FromArgb(255, 100, 100) : node.Color;

                using (var glowBrush = new SolidBrush(Color.FromArgb(glowAlpha, glowColor)))
                {
                    var glowRect = new Rectangle(monitorRect.X - 8, monitorRect.Y - 8,
                                               monitorRect.Width + 16, monitorRect.Height + 16);
                    g.FillRoundedRectangle(glowBrush, glowRect.X, glowRect.Y, glowRect.Width, glowRect.Height, 8);
                }
            }

            // Monitor body with gradient
            Color bodyColor1 = isHighPrivilege ? Color.FromArgb(80, 20, 20) : Color.FromArgb(30, 30, 50);
            Color bodyColor2 = isHighPrivilege ? Color.FromArgb(40, 10, 10) : Color.FromArgb(15, 15, 25);

            using (var brush = new LinearGradientBrush(monitorRect, bodyColor1, bodyColor2, 45f))
            {
                g.FillRoundedRectangle(brush, monitorRect.X, monitorRect.Y, monitorRect.Width, monitorRect.Height, 6);
            }

            // Screen area
            var screenRect = new Rectangle(monitorRect.X + 4, monitorRect.Y + 4,
                                         monitorRect.Width - 8, monitorRect.Height - 12);

            using (var brush = new SolidBrush(node.Color))
            {
                g.FillRectangle(brush, screenRect);
            }

            // Screen content based on privilege level
            if (isHighPrivilege)
            {
                DrawHackerScreen(g, screenRect, node);
            }
            else
            {
                DrawNormalScreen(g, screenRect);
            }

            // Monitor border
            Color borderColor = isHighPrivilege ? Color.FromArgb(255, 150, 150) : Color.FromArgb(100, 150, 255);
            using (var pen = new Pen(borderColor, 2.5f))
            {
                g.DrawRoundedRectangle(pen, monitorRect.X, monitorRect.Y, monitorRect.Width, monitorRect.Height, 6);
            }

            // Stand and base
            DrawMonitorStand(g, pos, size, isHighPrivilege);
        }

        private void DrawHackerScreen(Graphics g, Rectangle screenRect, BeaconNode node)
        {
            // Matrix-style falling code effect
            using (var font = new Font("Consolas", 6, FontStyle.Bold))
            using (var brush = new SolidBrush(Color.FromArgb(0, 255, 100)))
            {
                var chars = "01ABCDEF";
                for (int x = 0; x < screenRect.Width; x += 8)
                {
                    for (int y = 0; y < screenRect.Height; y += 10)
                    {
                        if (_random.NextDouble() < 0.3)
                        {
                            var c = chars[_random.Next(chars.Length)];
                            var alpha = (int)(Math.Sin(_animationTime * 10 + x + y) * 127 + 128);
                            using (var fadeBrush = new SolidBrush(Color.FromArgb(alpha, 0, 255, 100)))
                            {
                                g.DrawString(c.ToString(), font, fadeBrush, screenRect.X + x, screenRect.Y + y);
                            }
                        }
                    }
                }
            }

            // Skull overlay for system-level access
            if (node.NodeType == NodeType.SystemLevel)
            {
                using (var font = new Font("Segoe UI Symbol", 14, FontStyle.Bold))
                using (var brush = new SolidBrush(Color.FromArgb(200, 255, 50, 50)))
                {
                    var skull = "💀";
                    var textSize = g.MeasureString(skull, font);
                    g.DrawString(skull, font, brush,
                               screenRect.X + screenRect.Width / 2 - textSize.Width / 2,
                               screenRect.Y + screenRect.Height / 2 - textSize.Height / 2);
                }
            }
        }

        private void DrawNormalScreen(Graphics g, Rectangle screenRect)
        {
            // Windows logo
            var logoSize = Math.Min(screenRect.Width, screenRect.Height) / 3;
            var centerX = screenRect.X + screenRect.Width / 2;
            var centerY = screenRect.Y + screenRect.Height / 2;

            using (var brush = new SolidBrush(Color.FromArgb(100, 150, 255)))
            {
                var quadSize = logoSize / 2 - 1;
                g.FillRectangle(brush, centerX - logoSize / 2, centerY - logoSize / 2, quadSize, quadSize);
                g.FillRectangle(brush, centerX + 1, centerY - logoSize / 2, quadSize, quadSize);
                g.FillRectangle(brush, centerX - logoSize / 2, centerY + 1, quadSize, quadSize);
                g.FillRectangle(brush, centerX + 1, centerY + 1, quadSize, quadSize);
            }

            // Activity indicators
            DrawActivityDots(g, screenRect);
        }

        private void DrawActivityDots(Graphics g, Rectangle screenRect)
        {
            var dotColors = new[] { Color.Green, Color.Orange, Color.Red };
            for (int i = 0; i < 3; i++)
            {
                var pulse = (float)(Math.Sin(_animationTime * 6 + i) * 0.5 + 0.5);
                var alpha = Math.Max(50, Math.Min(255, (int)(200 * pulse)));
                using (var brush = new SolidBrush(Color.FromArgb(alpha, dotColors[i])))
                {
                    g.FillEllipse(brush,
                        screenRect.Right - 20 - (i * 8),
                        screenRect.Top + 5,
                        4, 4);
                }
            }
        }

        private void DrawMonitorStand(Graphics g, Point pos, int size, bool isHighPrivilege)
        {
            Color standColor = isHighPrivilege ? Color.FromArgb(120, 40, 40) : Color.FromArgb(60, 60, 80);

            // Stand neck
            var standRect = new Rectangle(pos.X - 3, pos.Y + size / 4, 6, size / 4);
            using (var brush = new SolidBrush(standColor))
            {
                g.FillRectangle(brush, standRect);
            }

            // Base with rounded corners
            var baseRect = new Rectangle(pos.X - size / 3, standRect.Bottom - 2, size * 2 / 3, 8);
            using (var brush = new LinearGradientBrush(baseRect, standColor, Color.FromArgb(standColor.A, standColor.R / 2, standColor.G / 2, standColor.B / 2), 90f))
            {
                g.FillRoundedRectangle(brush, baseRect.X, baseRect.Y, baseRect.Width, baseRect.Height, 4);
            }
        }

        private void DrawEnhancedLinuxComputer(Graphics g, BeaconNode node, Point pos, int size)
        {
            bool isHighPrivilege = node.NodeType == NodeType.Administrator || node.NodeType == NodeType.SystemLevel;
            var laptopRect = new Rectangle(pos.X - size / 2, pos.Y - size / 3, size, (int)(size * 0.6));

            if (node.Status == NodeStatus.Active)
            {
                var pulse = (float)(Math.Sin(_animationTime * 8) * 0.4 + 0.6);
                var glowAlpha = Math.Max(40, Math.Min(120, (int)(80 * pulse)));
                var glowColor = isHighPrivilege ? Color.FromArgb(255, 100, 100) : Color.FromArgb(100, 255, 100);

                using (var glowBrush = new SolidBrush(Color.FromArgb(glowAlpha, glowColor)))
                {
                    var glowRect = new Rectangle(laptopRect.X - 6, laptopRect.Y - 6,
                                               laptopRect.Width + 12, laptopRect.Height + 12);
                    g.FillRoundedRectangle(glowBrush, glowRect.X, glowRect.Y, glowRect.Width, glowRect.Height, 8);
                }
            }

            // Laptop body
            Color bodyColor1 = isHighPrivilege ? Color.FromArgb(60, 20, 20) : Color.FromArgb(40, 40, 40);
            Color bodyColor2 = isHighPrivilege ? Color.FromArgb(30, 10, 10) : Color.FromArgb(20, 20, 20);

            using (var brush = new LinearGradientBrush(laptopRect, bodyColor1, bodyColor2, 45f))
            {
                g.FillRoundedRectangle(brush, laptopRect.X, laptopRect.Y, laptopRect.Width, laptopRect.Height, 6);
            }

            // Screen area
            var screenRect = new Rectangle(laptopRect.X + 3, laptopRect.Y + 3,
                                         laptopRect.Width - 6, laptopRect.Height - 8);

            using (var brush = new SolidBrush(Color.FromArgb(20, 20, 20)))
            {
                g.FillRectangle(brush, screenRect);
            }

            // Terminal content
            DrawTerminalContent(g, screenRect, node, isHighPrivilege);

            // Laptop border
            Color borderColor = isHighPrivilege ? Color.FromArgb(255, 150, 150) : Color.FromArgb(100, 255, 150);
            using (var pen = new Pen(borderColor, 2f))
            {
                g.DrawRoundedRectangle(pen, laptopRect.X, laptopRect.Y, laptopRect.Width, laptopRect.Height, 6);
            }

            // Keyboard area
            DrawKeyboard(g, pos, size, isHighPrivilege);
        }

        private void DrawTerminalContent(Graphics g, Rectangle screenRect, BeaconNode node, bool isHighPrivilege)
        {
            using (var font = new Font("Consolas", 6, FontStyle.Regular))
            {
                var textColor = isHighPrivilege ? Color.FromArgb(255, 100, 100) : Color.FromArgb(0, 255, 100);
                using (var brush = new SolidBrush(textColor))
                {
                    var lines = new[]
                    {
                        "$ whoami",
                        isHighPrivilege ? "root" : "user",
                        "$ ps aux",
                        "PID CPU MEM",
                        "1337 2.1 4.5"
                    };

                    for (int i = 0; i < Math.Min(lines.Length, screenRect.Height / 8); i++)
                    {
                        g.DrawString(lines[i], font, brush, screenRect.X + 2, screenRect.Y + 2 + (i * 8));
                    }

                    // Blinking cursor
                    if (Math.Sin(_animationTime * 8) > 0)
                    {
                        g.DrawString("█", font, brush, screenRect.X + 2, screenRect.Y + 2 + (lines.Length * 8));
                    }
                }
            }
        }

        private void DrawKeyboard(Graphics g, Point pos, int size, bool isHighPrivilege)
        {
            var keyboardRect = new Rectangle(pos.X - size / 2, pos.Y + size / 6, size, size / 4);
            Color keyboardColor = isHighPrivilege ? Color.FromArgb(40, 10, 10) : Color.FromArgb(30, 30, 30);

            using (var brush = new LinearGradientBrush(keyboardRect, keyboardColor,
                Color.FromArgb(keyboardColor.A, keyboardColor.R / 2, keyboardColor.G / 2, keyboardColor.B / 2), 90f))
            {
                g.FillRoundedRectangle(brush, keyboardRect.X, keyboardRect.Y, keyboardRect.Width, keyboardRect.Height, 3);
            }

            // Individual keys
            Color keyColor = isHighPrivilege ? Color.FromArgb(80, 20, 20) : Color.FromArgb(50, 50, 50);
            using (var keyBrush = new SolidBrush(keyColor))
            {
                for (int row = 0; row < 3; row++)
                {
                    var keysInRow = row == 1 ? 8 : 7;
                    for (int col = 0; col < keysInRow; col++)
                    {
                        var keySize = 4;
                        var keyX = keyboardRect.X + 4 + (col * 6) + (row == 1 ? 0 : 3);
                        var keyY = keyboardRect.Y + 3 + (row * 6);
                        g.FillRoundedRectangle(keyBrush, keyX, keyY, keySize, keySize, 1);
                    }
                }
            }

            // Trackpad
            var trackpadRect = new Rectangle(pos.X - 8, keyboardRect.Bottom - 8, 16, 6);
            using (var brush = new SolidBrush(Color.FromArgb(60, 60, 60)))
            {
                g.FillRoundedRectangle(brush, trackpadRect.X, trackpadRect.Y, trackpadRect.Width, trackpadRect.Height, 2);
            }
        }

        private void DrawEnhancedStatusIndicator(Graphics g, BeaconNode node, Point pos, int size)
        {
            var statusColor = GetStatusColor(node.Status);
            var indicatorSize = 16;
            var indicatorPos = new Point(pos.X + size / 2 - 8, pos.Y - size / 2 - 8);

            // Multiple glow layers for active nodes
            if (node.Status == NodeStatus.Active)
            {
                for (int i = 3; i >= 1; i--)
                {
                    var glowSize = indicatorSize + (i * 6);
                    var pulse = (float)(Math.Sin(_animationTime * 8 + i) * 0.3 + 0.7);
                    var glowAlpha = Math.Max(30, Math.Min(120, (int)(80 * pulse / i)));

                    using (var glowBrush = new SolidBrush(Color.FromArgb(glowAlpha, statusColor)))
                    {
                        g.FillEllipse(glowBrush,
                            indicatorPos.X - (glowSize - indicatorSize) / 2,
                            indicatorPos.Y - (glowSize - indicatorSize) / 2,
                            glowSize, glowSize);
                    }
                }
            }

            // Main indicator
            using (var brush = new SolidBrush(statusColor))
            {
                g.FillEllipse(brush, indicatorPos.X, indicatorPos.Y, indicatorSize, indicatorSize);
            }

            // Indicator border
            using (var pen = new Pen(Color.FromArgb(200, 255, 255, 255), 2f))
            {
                g.DrawEllipse(pen, indicatorPos.X, indicatorPos.Y, indicatorSize, indicatorSize);
            }
        }

        private void DrawEnhancedPrivilegeIndicator(Graphics g, BeaconNode node, Point center, int nodeSize)
        {
            var privilegeInfo = GetPrivilegeInfo(node.NodeType);
            if (string.IsNullOrEmpty(privilegeInfo.Symbol)) return;

            using (var font = new Font("Consolas", 8, FontStyle.Bold))
            using (var brush = new SolidBrush(privilegeInfo.Color))
            {
                var textSize = g.MeasureString(privilegeInfo.Symbol, font);
                var badgePos = new Point(
                    center.X - (int)textSize.Width / 2,
                    center.Y - nodeSize / 2 - (int)textSize.Height - 8);

                var badgeRect = new Rectangle(badgePos.X - 6, badgePos.Y - 3,
                                             (int)textSize.Width + 12, (int)textSize.Height + 6);

                // Badge glow
                if (node.NodeType == NodeType.SystemLevel || node.NodeType == NodeType.Administrator)
                {
                    var pulse = (float)(Math.Sin(_animationTime * 6) * 0.4 + 0.6);
                    var glowAlpha = Math.Max(50, Math.Min(150, (int)(120 * pulse)));
                    using (var glowBrush = new SolidBrush(Color.FromArgb(glowAlpha, privilegeInfo.Color)))
                    {
                        g.FillRoundedRectangle(glowBrush, badgeRect.X - 3, badgeRect.Y - 3,
                                             badgeRect.Width + 6, badgeRect.Height + 6, 8);
                    }
                }

                // Badge background
                var bgColor = Color.FromArgb(200, 20, 20, 40);
                if (node.NodeType == NodeType.SystemLevel || node.NodeType == NodeType.Administrator)
                {
                    bgColor = Color.FromArgb(220, 60, 20, 20);
                }

                using (var bgBrush = new SolidBrush(bgColor))
                {
                    g.FillRoundedRectangle(bgBrush, badgeRect.X, badgeRect.Y, badgeRect.Width, badgeRect.Height, 6);
                }

                // Badge border
                using (var borderPen = new Pen(privilegeInfo.Color, 1.5f))
                {
                    g.DrawRoundedRectangle(borderPen, badgeRect.X, badgeRect.Y, badgeRect.Width, badgeRect.Height, 6);
                }

                g.DrawString(privilegeInfo.Symbol, font, brush, badgePos);
            }
        }

        private (string Symbol, Color Color) GetPrivilegeInfo(NodeType nodeType)
        {
            return nodeType switch
            {
                NodeType.SystemLevel => ("SYSTEM", Color.FromArgb(255, 100, 100)),
                NodeType.Administrator => ("ADMIN", Color.FromArgb(255, 150, 100)),
                NodeType.DomainUser => ("DOMAIN", Color.FromArgb(150, 100, 255)),
                NodeType.StandardUser => ("USER", Color.FromArgb(100, 255, 150)),
                _ => ("", Color.White)
            };
        }

        private void DrawEncryptionIndicator(Graphics g, BeaconNode node, Point pos, int size)
        {
            if (node.ClientInfo == null) return;

            var isEncrypted = node.ClientInfo.IsEncrypted;
            var encIcon = isEncrypted ? "🔒" : "🔓";
            var encColor = isEncrypted ? Color.FromArgb(0, 255, 150) : Color.FromArgb(255, 150, 100);

            if (isEncrypted)
            {
                var pulse = (float)(Math.Sin(_animationTime * 6) * 0.3 + 0.7);
                var glowAlpha = Math.Max(50, Math.Min(150, (int)(100 * pulse)));
                using (var glowBrush = new SolidBrush(Color.FromArgb(glowAlpha, encColor)))
                {
                    using (var font = new Font("Segoe UI Emoji", 14, FontStyle.Bold))
                    {
                        g.DrawString(encIcon, font, glowBrush, pos.X + size / 2 + 2, pos.Y - size / 2 - 4);
                    }
                }
            }

            using (var font = new Font("Segoe UI Emoji", 12, FontStyle.Bold))
            using (var brush = new SolidBrush(encColor))
            {
                g.DrawString(encIcon, font, brush, pos.X + size / 2 + 4, pos.Y - size / 2 - 2);
            }
        }

        private void DrawSelectionHighlight(Graphics g, Point pos, int size)
        {
            var highlightRect = new Rectangle(pos.X - size / 2 - 12, pos.Y - size / 2 - 12,
                                            size + 24, size + 24);

            // Animated selection ring
            var pulse = (float)(Math.Sin(_animationTime * 10) * 0.5 + 0.5);
            var alpha = Math.Max(100, Math.Min(255, (int)(200 * pulse)));

            using (var pen = new Pen(Color.FromArgb(alpha, 0, 255, 200), 3f))
            {
                pen.DashStyle = DashStyle.Custom;
                pen.DashPattern = new float[] { 8f, 4f };
                pen.DashOffset = _animationTime * 10;
                g.DrawRoundedRectangle(pen, highlightRect.X, highlightRect.Y, highlightRect.Width, highlightRect.Height, 12);
            }

            // Selection corners
            var cornerSize = 8;
            var corners = new[]
            {
                new Point(highlightRect.Left, highlightRect.Top),
                new Point(highlightRect.Right - cornerSize, highlightRect.Top),
                new Point(highlightRect.Left, highlightRect.Bottom - cornerSize),
                new Point(highlightRect.Right - cornerSize, highlightRect.Bottom - cornerSize)
            };

            using (var brush = new SolidBrush(Color.FromArgb(alpha, 0, 255, 200)))
            {
                foreach (var corner in corners)
                {
                    g.FillRectangle(brush, corner.X, corner.Y, cornerSize, cornerSize);
                }
            }
        }

        private void DrawNodeLabel(Graphics g, BeaconNode node, Point pos)
        {
            using (var font = new Font("Segoe UI", 9, FontStyle.Bold))
            {
                var text = node.DisplayName;
                var textSize = g.MeasureString(text, font);
                var labelPos = new PointF(pos.X - textSize.Width / 2, pos.Y + 40);

                var labelRect = new RectangleF(labelPos.X - 8, labelPos.Y - 3,
                                             textSize.Width + 16, textSize.Height + 6);

                // Label glow for high-privilege nodes
                if (node.NodeType == NodeType.Administrator || node.NodeType == NodeType.SystemLevel)
                {
                    var pulse = (float)(Math.Sin(_animationTime * 4) * 0.3 + 0.7);
                    var glowAlpha = Math.Max(50, Math.Min(120, (int)(80 * pulse)));
                    using (var glowBrush = new SolidBrush(Color.FromArgb(glowAlpha, 255, 100, 100)))
                    {
                        g.FillRoundedRectangle(glowBrush, labelRect.X - 2, labelRect.Y - 2,
                                             labelRect.Width + 4, labelRect.Height + 4, 8);
                    }
                }

                // Label background
                var bgColor = node.NodeType == NodeType.Administrator || node.NodeType == NodeType.SystemLevel
                    ? Color.FromArgb(220, 40, 20, 20)
                    : Color.FromArgb(180, 20, 20, 40);

                using (var bgBrush = new SolidBrush(bgColor))
                {
                    g.FillRoundedRectangle(bgBrush, labelRect.X, labelRect.Y, labelRect.Width, labelRect.Height, 6);
                }

                // Label border
                var borderColor = GetConnectionColor(node);
                using (var borderPen = new Pen(Color.FromArgb(150, borderColor), 1f))
                {
                    g.DrawRoundedRectangle(borderPen, labelRect.X, labelRect.Y, labelRect.Width, labelRect.Height, 6);
                }

                // Label text
                var textColor = node.NodeType == NodeType.Administrator || node.NodeType == NodeType.SystemLevel
                    ? Color.FromArgb(255, 200, 200)
                    : Color.FromArgb(200, 220, 255);

                using (var textBrush = new SolidBrush(textColor))
                {
                    g.DrawString(text, font, textBrush, labelPos.X + 8, labelPos.Y + 3);
                }
            }
        }

        private void DrawGlitchEffects(Graphics g)
        {
            foreach (var kvp in _nodeGlitches)
            {
                var glitches = kvp.Value;
                foreach (var glitch in glitches)
                {
                    var alpha = Math.Max(50, Math.Min(200, (int)(255 * (1 - glitch.Timer / glitch.Duration))));
                    var glitchColor = Color.FromArgb(alpha, glitch.Color);

                    using (var brush = new SolidBrush(glitchColor))
                    {
                        // Random glitch rectangles
                        for (int i = 0; i < 5; i++)
                        {
                            var glitchRect = new Rectangle(
                                glitch.Area.X + _random.Next(-10, 10),
                                glitch.Area.Y + _random.Next(-10, 10),
                                _random.Next(5, 20),
                                _random.Next(2, 5)
                            );
                            g.FillRectangle(brush, glitchRect);
                        }
                    }
                }
            }
        }

        private void DrawUI(Graphics g)
        {
            DrawEnhancedLegend(g);
            DrawEnhancedStats(g);
            DrawEnhancedAlerts(g);
            DrawEnhancedControls(g);

            if (_showMetrics)
                DrawHealthMetrics(g);
        }

        private void DrawEnhancedLegend(Graphics g)
        {
            var legendItems = new[]
            {
                ("SERVER", Color.FromArgb(0, 255, 150)),
                ("SYSTEM", Color.FromArgb(255, 100, 100)),
                ("Admin", Color.FromArgb(255, 150, 100)),
                ("Domain", Color.FromArgb(150, 100, 255)),
                ("User", Color.FromArgb(100, 255, 150)),
                ("Encrypted", Color.FromArgb(0, 255, 150)),
                ("Plaintext", Color.FromArgb(255, 150, 100))
            };

            var startY = 15;
            var itemHeight = 24;
            var legendWidth = 180;
            var legendHeight = legendItems.Length * itemHeight + 20;

            using (var font = new Font("Segoe UI", 9, FontStyle.Bold))
            using (var textBrush = new SolidBrush(Color.FromArgb(220, 255, 255)))
            using (var bgBrush = new SolidBrush(Color.FromArgb(200, 10, 15, 25)))
            {
                // Legend background with glow
                using (var glowBrush = new SolidBrush(Color.FromArgb(50, 0, 150, 255)))
                {
                    g.FillRoundedRectangle(glowBrush, 10 - 3, startY - 3, legendWidth + 6, legendHeight + 6, 12);
                }

                g.FillRoundedRectangle(bgBrush, 10, startY, legendWidth, legendHeight, 10);

                // Legend border
                using (var borderPen = new Pen(Color.FromArgb(100, 0, 200, 255), 2f))
                {
                    g.DrawRoundedRectangle(borderPen, 10, startY, legendWidth, legendHeight, 10);
                }

                // Title
                using (var titleBrush = new SolidBrush(Color.FromArgb(255, 0, 255, 200)))
                using (var titleFont = new Font("Segoe UI", 10, FontStyle.Bold))
                {
                    g.DrawString("NETWORK LEGEND", titleFont, titleBrush, 20, startY + 5);
                }

                // Legend items
                for (int i = 0; i < legendItems.Length; i++)
                {
                    var y = startY + 25 + i * itemHeight;

                    // Color indicator with glow
                    using (var colorBrush = new SolidBrush(legendItems[i].Item2))
                    using (var glowBrush = new SolidBrush(Color.FromArgb(80, legendItems[i].Item2)))
                    {
                        g.FillEllipse(glowBrush, 18, y - 1, 16, 16);
                        g.FillEllipse(colorBrush, 20, y + 1, 12, 12);
                    }

                    g.DrawString(legendItems[i].Item1, font, textBrush, 40, y);
                }
            }
        }

        private void DrawEnhancedStats(Graphics g)
        {
            var stats = new[]
            {
                $"Active Beacons: {_beaconNodes.Count(n => n.Status == NodeStatus.Active)}/{_beaconNodes.Count}",
                $"Encrypted Links: {_beaconNodes.Count(n => n.ClientInfo?.IsEncrypted == true)}",
                $"High Privilege: {_beaconNodes.Count(n => n.NodeType == NodeType.Administrator || n.NodeType == NodeType.SystemLevel)}",
                $"Data Packets: {_networkPackets.Count}",
                $"Active Pulses: {_connectionPulses.Count}",
                $"Layout Mode: {_layoutMode}",
                $"Zoom Level: {_zoomLevel:F1}x",
                $"System Alerts: {_securityAlerts.Count}"
            };

            using (var font = new Font("Consolas", 9, FontStyle.Bold))
            using (var brush = new SolidBrush(Color.FromArgb(220, 255, 255)))
            using (var bgBrush = new SolidBrush(Color.FromArgb(200, 10, 15, 25)))
            {
                var maxWidth = stats.Max(s => g.MeasureString(s, font).Width);
                var statsHeight = stats.Length * 22 + 25;
                var statsRect = new Rectangle(Width - (int)maxWidth - 50, 15, (int)maxWidth + 40, statsHeight);

                // Stats background with glow
                using (var glowBrush = new SolidBrush(Color.FromArgb(50, 0, 150, 255)))
                {
                    g.FillRoundedRectangle(glowBrush, statsRect.X - 3, statsRect.Y - 3, statsRect.Width + 6, statsRect.Height + 6, 12);
                }

                g.FillRoundedRectangle(bgBrush, statsRect.X, statsRect.Y, statsRect.Width, statsRect.Height, 10);

                // Stats border
                using (var borderPen = new Pen(Color.FromArgb(100, 0, 200, 255), 2f))
                {
                    g.DrawRoundedRectangle(borderPen, statsRect.X, statsRect.Y, statsRect.Width, statsRect.Height, 10);
                }

                // Title
                using (var titleBrush = new SolidBrush(Color.FromArgb(255, 0, 255, 200)))
                using (var titleFont = new Font("Segoe UI", 10, FontStyle.Bold))
                {
                    g.DrawString("SYSTEM STATUS", titleFont, titleBrush, statsRect.X + 10, statsRect.Y + 5);
                }

                // Stats items
                for (int i = 0; i < stats.Length; i++)
                {
                    var color = i < 3 ? Color.FromArgb(220, 100, 255, 150) : Color.FromArgb(220, 200, 200, 255);
                    using (var statBrush = new SolidBrush(color))
                    {
                        g.DrawString(stats[i], font, statBrush, statsRect.X + 15, statsRect.Y + 25 + i * 22);
                    }
                }
            }
        }

        private void DrawEnhancedAlerts(Graphics g)
        {
            var y = Height - 150;
            var alertWidth = Width - 40;

            foreach (var alert in _securityAlerts.Take(6).Reverse())
            {
                var alpha = Math.Max(50, Math.Min(255, (int)(255 * (alert.FadeTimer / 8.0f))));
                var pulse = (float)(Math.Sin(alert.PulsePhase) * 0.3 + 0.7);

                var alertColor = alert.Level switch
                {
                    AlertLevel.Critical => Color.FromArgb((int)(alpha * pulse), 255, 100, 100),
                    AlertLevel.Warning => Color.FromArgb((int)(alpha * pulse), 255, 200, 100),
                    AlertLevel.Success => Color.FromArgb((int)(alpha * pulse), 100, 255, 150),
                    AlertLevel.Info => Color.FromArgb((int)(alpha * pulse), 100, 200, 255),
                    _ => Color.FromArgb(alpha, 255, 255, 255)
                };

                using (var font = new Font("Consolas", 8, FontStyle.Bold))
                using (var brush = new SolidBrush(alertColor))
                using (var bgBrush = new SolidBrush(Color.FromArgb(Math.Min(180, alpha), 0, 0, 0)))
                {
                    var text = $"[{alert.Timestamp:HH:mm:ss}] {alert.Level.ToString().ToUpper()}: {alert.Message}";
                    var textSize = g.MeasureString(text, font);
                    var rect = new RectangleF(20, y, textSize.Width + 20, textSize.Height + 8);

                    // Alert glow for critical alerts
                    if (alert.Level == AlertLevel.Critical)
                    {
                        using (var glowBrush = new SolidBrush(Color.FromArgb((int)(alpha * pulse / 4), 255, 50, 50)))
                        {
                            g.FillRoundedRectangle(glowBrush, rect.X - 5, rect.Y - 5, rect.Width + 10, rect.Height + 10, 8);
                        }
                    }

                    g.FillRoundedRectangle(bgBrush, rect.X, rect.Y, rect.Width, rect.Height, 5);

                    // Alert border
                    using (var borderPen = new Pen(Color.FromArgb(alpha, alertColor), 1f))
                    {
                        g.DrawRoundedRectangle(borderPen, rect.X, rect.Y, rect.Width, rect.Height, 5);
                    }

                    g.DrawString(text, font, brush, rect.X + 10, rect.Y + 4);
                }

                y -= 25;
            }
        }

        private void DrawEnhancedControls(Graphics g)
        {
            var controls = new[]
            {
                "G - Toggle Grid Display",
                "M - Toggle Performance Metrics",
                "L - Cycle Layout Modes",
                "R - Reset Node Positions",
                "C - Centre Network View",
                "E - Trigger System Glitch"
            };

            using (var font = new Font("Consolas", 8))
            using (var brush = new SolidBrush(Color.FromArgb(180, 200, 255, 200)))
            using (var bgBrush = new SolidBrush(Color.FromArgb(150, 10, 15, 25)))
            {
                var maxWidth = controls.Max(c => g.MeasureString(c, font).Width);
                var controlsHeight = controls.Length * 16 + 20;
                var rect = new RectangleF(15, Height - controlsHeight - 15, maxWidth + 20, controlsHeight);

                // Controls background
                g.FillRoundedRectangle(bgBrush, rect.X, rect.Y, rect.Width, rect.Height, 8);

                // Controls border
                using (var borderPen = new Pen(Color.FromArgb(80, 100, 200, 255), 1f))
                {
                    g.DrawRoundedRectangle(borderPen, rect.X, rect.Y, rect.Width, rect.Height, 8);
                }

                // Title
                using (var titleBrush = new SolidBrush(Color.FromArgb(200, 150, 200, 255)))
                using (var titleFont = new Font("Segoe UI", 9, FontStyle.Bold))
                {
                    g.DrawString("CONTROLS", titleFont, titleBrush, rect.X + 8, rect.Y + 5);
                }

                // Control items
                for (int i = 0; i < controls.Length; i++)
                {
                    g.DrawString(controls[i], font, brush, rect.X + 10, rect.Y + 20 + (i * 16));
                }
            }
        }

        private void DrawHealthMetrics(Graphics g)
        {
            foreach (var node in _beaconNodes)
            {
                if (!_nodeHealthMetrics.ContainsKey(node.Id)) continue;

                var pos = GetScreenPosition(node.Position);
                var health = _nodeHealthMetrics[node.Id];
                var barWidth = 50;
                var barHeight = 8;

                var barRect = new Rectangle(pos.X - barWidth / 2, pos.Y + 28, barWidth, barHeight);

                // Health bar background
                using (var brush = new SolidBrush(Color.FromArgb(120, 40, 40, 40)))
                {
                    g.FillRoundedRectangle(brush, barRect.X, barRect.Y, barRect.Width, barRect.Height, 4);
                }

                // Health bar fill
                var healthWidth = (int)(barWidth * health);
                var healthColor = health > 0.7f ? Color.FromArgb(100, 255, 150) :
                                 health > 0.3f ? Color.FromArgb(255, 200, 100) :
                                                Color.FromArgb(255, 100, 100);

                using (var brush = new SolidBrush(Color.FromArgb(200, healthColor)))
                {
                    if (healthWidth > 0)
                    {
                        g.FillRoundedRectangle(brush, barRect.X, barRect.Y, healthWidth, barRect.Height, 4);
                    }
                }

                // Health bar border
                using (var pen = new Pen(Color.FromArgb(150, 200, 200, 255), 1f))
                {
                    g.DrawRoundedRectangle(pen, barRect.X, barRect.Y, barRect.Width, barRect.Height, 4);
                }

                // Health percentage text
                using (var font = new Font("Consolas", 7, FontStyle.Bold))
                using (var textBrush = new SolidBrush(Color.FromArgb(200, 255, 255, 255)))
                {
                    var healthText = $"{health:P0}";
                    var textSize = g.MeasureString(healthText, font);
                    g.DrawString(healthText, font, textBrush,
                               barRect.X + barRect.Width / 2 - textSize.Width / 2,
                               barRect.Y - textSize.Height - 2);
                }
            }
        }

        // Utility methods
        public void CenterView()
        {
            _viewCenter = new Point(Width / 2, Height / 2);
            _serverNode.Position = new Vector2(0, 0);
            _zoomLevel = 1.0f;
            Invalidate();
        }

        public void ResetBeaconPositions()
        {
            _serverNode.Position = new Vector2(0, 0);
            ApplyLayout();

            foreach (var node in _beaconNodes)
            {
                if (_velocities.ContainsKey(node))
                {
                    _velocities[node] = new Vector2();
                }
            }
            Invalidate();
        }

        private void OnResize(object sender, EventArgs e)
        {
            _viewCenter = new Point(Width / 2, Height / 2);
            InitializeStars();
            RepositionNodesInBounds();
            Invalidate();
        }

        private void RepositionNodesInBounds()
        {
            if (_beaconNodes.Count == 0) return;

            var maxRadius = Math.Min(Width, Height) * 0.3f;
            var centerX = Width / 2f;
            var centerY = Height / 2f;

            var serverScreenPos = GetScreenPosition(_serverNode.Position);
            if (Math.Abs(serverScreenPos.X - centerX) > 100 || Math.Abs(serverScreenPos.Y - centerY) > 100)
            {
                _serverNode.Position = new Vector2(0, 0);
            }

            for (int i = 0; i < _beaconNodes.Count; i++)
            {
                var node = _beaconNodes[i];
                var distance = Vector2.Distance(node.Position, _serverNode.Position);

                if (distance > maxRadius)
                {
                    var angle = (float)(i * 2 * Math.PI / _beaconNodes.Count);
                    var newRadius = 140f + (i % 4) * 30f;

                    node.Position = new Vector2(
                        _serverNode.Position.X + (float)(Math.Cos(angle) * newRadius),
                        _serverNode.Position.Y + (float)(Math.Sin(angle) * newRadius)
                    );

                    if (_velocities.ContainsKey(node))
                    {
                        _velocities[node] = new Vector2();
                    }
                }
            }
        }

        private Point GetScreenPosition(Vector2 position)
        {
            return new Point(
                (int)(_viewCenter.X + position.X * _zoomLevel),
                (int)(_viewCenter.Y + position.Y * _zoomLevel));
        }

        private int GetNodeSize(BeaconNode node)
        {
            var baseSize = node.NodeType == NodeType.Server ? 80 : 60;
            return (int)(baseSize * _zoomLevel);
        }

        private Color GetStatusColor(NodeStatus status)
        {
            return status switch
            {
                NodeStatus.Active => Color.FromArgb(100, 255, 150),
                NodeStatus.Inactive => Color.FromArgb(255, 100, 100),
                NodeStatus.Warning => Color.FromArgb(255, 200, 100),
                _ => Color.FromArgb(150, 150, 150)
            };
        }

        // Mouse and interaction handlers
        private void OnMouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                var clickedNode = GetNodeAtPosition(e.Location);
                if (clickedNode != null)
                {
                    _draggedNode = clickedNode;
                    _dragStart = e.Location;
                    _isDragging = true;

                    if (clickedNode.NodeType != NodeType.Server)
                    {
                        foreach (var node in _beaconNodes)
                            node.IsSelected = false;
                        clickedNode.IsSelected = true;
                        BeaconSelected?.Invoke(this, new BeaconSelectedEventArgs(clickedNode.Id));
                    }

                    Invalidate();
                }
            }
        }

        private void OnMouseMove(object sender, MouseEventArgs e)
        {
            if (_isDragging && _draggedNode != null)
            {
                var deltaX = (e.X - _dragStart.X) / _zoomLevel;
                var deltaY = (e.Y - _dragStart.Y) / _zoomLevel;

                _draggedNode.Position = new Vector2(
                    _draggedNode.Position.X + deltaX,
                    _draggedNode.Position.Y + deltaY);

                _dragStart = e.Location;
                Invalidate();
            }
            else
            {
                var nodeUnderMouse = GetNodeAtPosition(e.Location);
                Cursor = nodeUnderMouse != null ? Cursors.Hand : Cursors.Default;

                if (nodeUnderMouse != null)
                {
                    ShowNodeTooltip(nodeUnderMouse, e.Location);
                }
            }
        }

        private void ShowNodeTooltip(BeaconNode node, Point mousePos)
        {
            var health = _nodeHealthMetrics.ContainsKey(node.Id) ? _nodeHealthMetrics[node.Id] : 1.0f;
            var tooltipText = $"{node.DisplayName}\n" +
                            $"Status: {node.Status}\n" +
                            $"Type: {node.NodeType}\n" +
                            $"Health: {health:P0}\n" +
                            $"OS: {(node.ClientInfo?.IsLinux == true ? "Linux" : "Windows")}\n" +
                            $"Encrypted: {(node.ClientInfo?.IsEncrypted == true ? "Yes" : "No")}";
            _tooltip.SetToolTip(this, tooltipText);
        }

        private void OnMouseUp(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left && _isDragging)
            {
                _isDragging = false;
                _draggedNode = null;
            }
        }

        private void OnMouseWheel(object sender, MouseEventArgs e)
        {
            var zoomFactor = e.Delta > 0 ? 1.15f : 0.85f;
            _zoomLevel = Math.Max(0.2f, Math.Min(4.0f, _zoomLevel * zoomFactor));
            Invalidate();
        }

        protected override void OnDoubleClick(EventArgs e)
        {
            var mousePos = PointToClient(MousePosition);
            var clickedNode = GetNodeAtPosition(mousePos);

            if (clickedNode != null && clickedNode.NodeType != NodeType.Server)
            {
                BeaconDoubleClicked?.Invoke(this, new BeaconDoubleClickEventArgs(clickedNode.Id));
            }
        }

        public BeaconNode GetNodeAtPosition(Point position)
        {
            var serverPos = GetScreenPosition(_serverNode.Position);
            var serverSize = GetNodeSize(_serverNode);
            if (Vector2.Distance(new Vector2(position.X, position.Y),
                                new Vector2(serverPos.X, serverPos.Y)) <= serverSize / 2)
            {
                return _serverNode;
            }

            foreach (var node in _beaconNodes)
            {
                var nodePos = GetScreenPosition(node.Position);
                var nodeSize = GetNodeSize(node);

                if (Vector2.Distance(new Vector2(position.X, position.Y),
                                   new Vector2(nodePos.X, nodePos.Y)) <= nodeSize / 2)
                {
                    return node;
                }
            }

            return null;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _animationTimer?.Stop();
                _animationTimer?.Dispose();
                _privilegeRefreshTimer?.Stop();
                _privilegeRefreshTimer?.Dispose();
                _tooltip?.Dispose();
            }
            base.Dispose(disposing);
        }

        private void NetworkTopologyViewer_Load(object sender, EventArgs e)
        {
            Focus(); // Ensure the control can receive keyboard input
        }
    }

    public class BeaconNode
    {
        public string Id { get; set; }
        public string DisplayName { get; set; }
        public Vector2 Position { get; set; }
        public NodeType NodeType { get; set; }
        public NodeStatus Status { get; set; }
        public Color Color { get; set; }
        public bool IsSelected { get; set; }
        public bool IsFixed { get; set; }
        public ClientInfo ClientInfo { get; set; }
        public DateTime LastActivity { get; set; } = DateTime.Now;
    }

    public enum NodeType
    {
        Server,
        SystemLevel,
        Administrator,
        DomainUser,
        StandardUser
    }

    public enum NodeStatus
    {
        Active,
        Inactive,
        Warning,
        Error
    }

    public struct Vector2
    {
        public float X, Y;

        public Vector2(float x = 0, float y = 0)
        {
            X = x; Y = y;
        }

        public static Vector2 Add(Vector2 a, Vector2 b) => new Vector2(a.X + b.X, a.Y + b.Y);
        public static Vector2 Subtract(Vector2 a, Vector2 b) => new Vector2(a.X - b.X, a.Y - b.Y);
        public static Vector2 Multiply(Vector2 v, float scalar) => new Vector2(v.X * scalar, v.Y * scalar);
        public static Vector2 Normalize(Vector2 v)
        {
            var length = v.Length();
            return length > 0 ? new Vector2(v.X / length, v.Y / length) : new Vector2();
        }

        public float Length() => (float)Math.Sqrt(X * X + Y * Y);

        public static float Distance(Vector2 a, Vector2 b)
        {
            var dx = a.X - b.X;
            var dy = a.Y - b.Y;
            return (float)Math.Sqrt(dx * dx + dy * dy);
        }
    }

    public class BeaconSelectedEventArgs : EventArgs
    {
        public string BeaconId { get; }
        public BeaconSelectedEventArgs(string beaconId) => BeaconId = beaconId;
    }

    public class BeaconDoubleClickEventArgs : EventArgs
    {
        public string BeaconId { get; }
        public BeaconDoubleClickEventArgs(string beaconId) => BeaconId = beaconId;
    }

    public class ClientInfo
    {
        public string ClientId { get; set; }
        public string ClientInfo_ { get; set; }
        public string UserName { get; set; }
        public string ComputerName { get; set; }
        public bool IsAdmin { get; set; }
        public bool IsConnected { get; set; }
        public bool IsEncrypted { get; set; }
        public string OSVersion { get; set; }
        public bool IsLinux { get; set; }
        public DateTime LastSeen { get; set; }
        public bool IsDomainJoined { get; set; }
    }

    public static class GraphicsExtensions
    {
        public static void FillRoundedRectangle(this Graphics g, Brush brush, float x, float y, float width, float height, float radius)
        {
            using (var path = new GraphicsPath())
            {
                if (radius > 0 && width > radius * 2 && height > radius * 2)
                {
                    path.AddArc(x, y, radius * 2, radius * 2, 180, 90);
                    path.AddArc(x + width - radius * 2, y, radius * 2, radius * 2, 270, 90);
                    path.AddArc(x + width - radius * 2, y + height - radius * 2, radius * 2, radius * 2, 0, 90);
                    path.AddArc(x, y + height - radius * 2, radius * 2, radius * 2, 90, 90);
                    path.CloseAllFigures();
                }
                else
                {
                    path.AddRectangle(new RectangleF(x, y, width, height));
                }
                g.FillPath(brush, path);
            }
        }

        public static void DrawRoundedRectangle(this Graphics g, Pen pen, float x, float y, float width, float height, float radius)
        {
            using (var path = new GraphicsPath())
            {
                if (radius > 0 && width > radius * 2 && height > radius * 2)
                {
                    path.AddArc(x, y, radius * 2, radius * 2, 180, 90);
                    path.AddArc(x + width - radius * 2, y, radius * 2, radius * 2, 270, 90);
                    path.AddArc(x + width - radius * 2, y + height - radius * 2, radius * 2, radius * 2, 0, 90);
                    path.AddArc(x, y + height - radius * 2, radius * 2, radius * 2, 90, 90);
                    path.CloseAllFigures();
                }
                else
                {
                    path.AddRectangle(new RectangleF(x, y, width, height));
                }
                g.DrawPath(pen, path);
            }
        }
    }
}