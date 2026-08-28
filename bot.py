import discord
from discord import app_commands
import os, json, re, time
from collections import defaultdict, deque
from datetime import datetime, timezone

DATA_DIR = os.getenv("RAILWAY_VOLUME_MOUNT_PATH", ".")
os.makedirs(DATA_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(DATA_DIR, "innocent_config.json")
HISTORY_FILE = os.path.join(DATA_DIR, "innocent_history.json")
OWNER_USER_ID = int(os.getenv("OWNER_USER_ID", "0") or 0)

# -------------------- Detection tuning --------------------

SPAM_WINDOW = 8
SPAM_LIMIT = 6

DUP_WINDOW = 20
DUP_LIMIT = 3

MENTION_LIMIT = 5
EMOJI_LIMIT = 14
CAPS_MIN_LETTERS = 18
CAPS_RATIO = 0.82
REPEAT_CHAR_LIMIT = 12
LONG_MESSAGE_LIMIT = 1500
NEWLINE_LIMIT = 18

ALERT_COOLDOWN = 20

INVITE_RE = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/[A-Za-z0-9-]+",
    re.I
)

URL_RE = re.compile(r"https?://\S+", re.I)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)")

# Common suspicious executable/archive file extensions.
SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".msi", ".jar",
    ".ps1", ".vbs", ".js", ".zip", ".rar", ".7z"
}

# This is deliberately limited to high-confidence patterns.
# It does NOT try to decide every argument/insult automatically.
THREAT_PATTERNS = [
    re.compile(r"\bi(?:'m| am)?\s+going\s+to\s+(?:hurt|attack|kill)\s+you\b", re.I),
    re.compile(r"\bi(?:'ll| will)\s+(?:hurt|attack|kill)\s+you\b", re.I),
    re.compile(r"\byou\s+should\s+(?:die|get hurt)\b", re.I),
]

HARASSMENT_PATTERNS = [
    re.compile(r"\bshut\s+up\b.{0,35}\b(?:idiot|stupid|loser)\b", re.I),
    re.compile(r"\bnobody\s+likes\s+you\b", re.I),
    re.compile(r"\beveryone\s+hates\s+you\b", re.I),
]

SCAM_PATTERNS = [
    re.compile(r"\bfree\s+(?:nitro|robux)\b", re.I),
    re.compile(r"\bclaim\s+(?:your|this)\s+(?:prize|reward)\b", re.I),
    re.compile(r"\bsteam\s+gift\b", re.I),
    re.compile(r"\bverify\s+your\s+account\b", re.I),
]

RULES = {
    1: "Respect Everyone",
    2: "Keep It Appropriate",
    3: "No Spamming",
    4: "No Advertising",
    5: "Use Channels Correctly",
    6: "No Harmful Content",
    7: "Respect Privacy",
    8: "Don't Cause Drama",
    9: "Don't Abuse Support",
    10: "Respect Staff Decisions",
    11: "Follow In-Game Rules",
    12: "Use Common Sense",
}

def load_json(path, fallback):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return fallback

config = load_json(CONFIG_FILE, {"guilds": {}})
history = load_json(HISTORY_FILE, [])

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def guild_cfg(gid):
    key = str(gid)
    if key not in config["guilds"]:
        config["guilds"][key] = {
            "moderator_role_id": None,
            "log_channel_id": None,
            "enabled": True,
            "privacy_alerts": False,
            "weird_message_detection": True,
        }
        save_json(CONFIG_FILE, config)
    return config["guilds"][key]

class InnocentBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        intents.presences = True
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        synced = await self.tree.sync()
        print(f"Synced {len(synced)} Airi Innocent command(s).")

bot = InnocentBot()

message_times = defaultdict(lambda: deque(maxlen=30))
recent_messages = defaultdict(lambda: deque(maxlen=15))
cooldowns = {}

def is_staff(member):
    p = member.guild_permissions
    return p.manage_messages or p.manage_guild or p.administrator

def alert_allowed(gid, uid, rule, tag):
    key = (gid, uid, rule, tag)
    now = time.monotonic()
    if now - cooldowns.get(key, 0) < ALERT_COOLDOWN:
        return False
    cooldowns[key] = now
    return True

def add_history(guild_id, user_id, rule, reason, source, message=None):
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "guild_id": guild_id,
        "user_id": user_id,
        "rule": rule,
        "reason": reason,
        "source": source,
        "message_id": message.id if message else None,
        "channel_id": message.channel.id if message else None,
    })
    if len(history) > 5000:
        del history[:-5000]
    save_json(HISTORY_FILE, history)

def count_unicode_emojis(text):
    count = 0
    for ch in text:
        code = ord(ch)
        if (
            0x1F300 <= code <= 0x1FAFF
            or 0x2600 <= code <= 0x26FF
            or 0x2700 <= code <= 0x27BF
        ):
            count += 1
    # custom Discord emoji
    count += len(re.findall(r"<a?:\w+:\d+>", text))
    return count

def excessive_caps(text):
    letters = [c for c in text if c.isalpha()]
    if len(letters) < CAPS_MIN_LETTERS:
        return False
    uppercase = sum(1 for c in letters if c.isupper())
    return uppercase / len(letters) >= CAPS_RATIO

def suspicious_repeated_chars(text):
    return re.search(r"(.)\1{" + str(REPEAT_CHAR_LIMIT - 1) + r",}", text) is not None

def normalized_message(text):
    return re.sub(r"\s+", " ", text.lower()).strip()

async def get_log_channel(guild):
    cid = guild_cfg(guild.id).get("log_channel_id")
    return guild.get_channel(cid) if cid else None

async def alert(member, channel, rule, reason, message=None, source="automatic", tag="general"):
    if not alert_allowed(member.guild.id, member.id, rule, tag):
        return

    cfg = guild_cfg(member.guild.id)
    role = member.guild.get_role(cfg.get("moderator_role_id")) if cfg.get("moderator_role_id") else None

    mention_text = member.mention
    if role:
        mention_text += f" {role.mention}"

    embed = discord.Embed(
        title="🌸 Airi Innocent detected a possible rule break",
        description=(
            f"{member.mention}, please stop and review **Rule {rule} — {RULES[rule]}**.\n\n"
            f"**Detected:** {reason}\n\n"
            "Moderators have been notified to review it."
        ),
        color=discord.Color.from_rgb(255, 182, 193),
        timestamp=datetime.now(timezone.utc),
    )
    embed.set_footer(text="Airi Innocent • Automatic detection may be reviewed by staff.")

    try:
        await channel.send(
            content=mention_text,
            embed=embed,
            allowed_mentions=discord.AllowedMentions(users=True, roles=True, everyone=False),
        )
    except Exception:
        pass

    add_history(member.guild.id, member.id, rule, reason, source, message)

    lc = await get_log_channel(member.guild)
    if lc:
        e = discord.Embed(
            title="🌸 Airi Innocent — Snitch Log",
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc),
        )
        e.add_field(name="Offender", value=f"{member.mention}\n`{member.id}`", inline=False)
        e.add_field(name="Rule", value=f"Rule {rule} — {RULES[rule]}", inline=False)
        e.add_field(name="Reason", value=reason[:1024], inline=False)
        e.add_field(name="Detection", value=source, inline=False)
        if message:
            content = message.content.strip() or "*No message text*"
            e.add_field(name="Message Content", value=content[:900], inline=False)
            e.add_field(name="Jump", value=f"[Go to message]({message.jump_url})", inline=False)
        try:
            await lc.send(embed=e)
        except Exception:
            pass

@bot.event
async def on_message(message):
    if not message.guild or message.author.bot:
        return
    if not isinstance(message.author, discord.Member):
        return

    cfg = guild_cfg(message.guild.id)

    if not cfg.get("enabled", True):
        return

    # Staff are exempt from automatic detection.
    if is_staff(message.author):
        return

    uid_key = (message.guild.id, message.author.id)
    now = time.monotonic()
    text = message.content or ""

    # ========================================================
    # RULE 3 — SPAM
    # ========================================================

    times = message_times[uid_key]
    times.append(now)

    while times and now - times[0] > SPAM_WINDOW:
        times.popleft()

    if len(times) >= SPAM_LIMIT:
        await alert(
            message.author, message.channel, 3,
            f"Sent {len(times)} messages in about {SPAM_WINDOW} seconds.",
            message, tag="fast_spam"
        )
        times.clear()
        return

    norm = normalized_message(text)

    if norm:
        recents = recent_messages[uid_key]
        recents.append((norm, now))

        while recents and now - recents[0][1] > DUP_WINDOW:
            recents.popleft()

        duplicate_count = sum(1 for msg, _ in recents if msg == norm)

        if duplicate_count >= DUP_LIMIT:
            await alert(
                message.author, message.channel, 3,
                "Repeated the same message several times.",
                message, tag="duplicates"
            )
            recents.clear()
            return

    mention_count = len(message.mentions) + len(message.role_mentions)

    if message.mention_everyone:
        mention_count += MENTION_LIMIT

    if mention_count >= MENTION_LIMIT:
        await alert(
            message.author, message.channel, 3,
            f"Used {mention_count} mentions in one message.",
            message, tag="mentions"
        )
        return

    emoji_count = count_unicode_emojis(text)

    if emoji_count >= EMOJI_LIMIT:
        await alert(
            message.author, message.channel, 3,
            f"Used about {emoji_count} emojis in one message.",
            message, tag="emoji_flood"
        )
        return

    # ========================================================
    # RULE 4 — ADVERTISING
    # ========================================================

    if INVITE_RE.search(text):
        await alert(
            message.author, message.channel, 4,
            "Posted a Discord invite link without staff permission.",
            message, tag="discord_invite"
        )
        return

    # ========================================================
    # RULE 6 — HARMFUL / SUSPICIOUS CONTENT
    # ========================================================

    if any(p.search(text) for p in SCAM_PATTERNS):
        await alert(
            message.author, message.channel, 6,
            "Message resembles a common scam or suspicious giveaway pattern.",
            message, tag="scam"
        )
        return

    suspicious_attachments = []
    for attachment in message.attachments:
        filename = attachment.filename.lower()
        for ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            if filename.endswith(ext):
                suspicious_attachments.append(attachment.filename)
                break

    if suspicious_attachments:
        await alert(
            message.author, message.channel, 6,
            "Posted a potentially risky attachment: " + ", ".join(suspicious_attachments[:3]),
            message, tag="attachment"
        )
        return

    # ========================================================
    # RULE 1 — HIGH-CONFIDENCE HARASSMENT / THREATS
    # ========================================================

    if any(p.search(text) for p in THREAT_PATTERNS):
        await alert(
            message.author, message.channel, 1,
            "Message contains language that appears to threaten another person.",
            message, tag="threat"
        )
        return

    if any(p.search(text) for p in HARASSMENT_PATTERNS):
        await alert(
            message.author, message.channel, 1,
            "Message appears to directly insult or target another member.",
            message, tag="harassment"
        )
        return

    # ========================================================
    # RULE 7 — OPTIONAL PRIVACY ALERTS
    # ========================================================

    if cfg.get("privacy_alerts", False):
        if EMAIL_RE.search(text) or IP_RE.search(text) or PHONE_RE.search(text):
            await alert(
                message.author, message.channel, 7,
                "Possible personal information was posted. Staff should verify whether it belongs here.",
                message, tag="privacy"
            )
            return

    # ========================================================
    # RULE 12 — WEIRD / DISRUPTIVE MESSAGE DETECTION
    # ========================================================

    if cfg.get("weird_message_detection", True):
        if excessive_caps(text):
            await alert(
                message.author, message.channel, 12,
                "Message is overwhelmingly written in capital letters and may be disruptive.",
                message, tag="caps"
            )
            return

        if suspicious_repeated_chars(text):
            await alert(
                message.author, message.channel, 12,
                "Message contains an excessive repeated-character string.",
                message, tag="repeat_chars"
            )
            return

        if len(text) >= LONG_MESSAGE_LIMIT:
            await alert(
                message.author, message.channel, 12,
                f"Posted an unusually large message ({len(text)} characters).",
                message, tag="wall"
            )
            return

        if text.count("\n") >= NEWLINE_LIMIT:
            await alert(
                message.author, message.channel, 12,
                "Posted a message with an excessive number of line breaks.",
                message, tag="newlines"
            )
            return

# ============================================================
# COMMANDS
# ============================================================

@bot.tree.command(name="innocent-setup", description="Configure Airi Innocent.")
@app_commands.describe(
    moderator_role="Role Airi should ping for rule alerts.",
    log_channel="Private channel where Airi logs alerts."
)
async def innocent_setup(
    interaction: discord.Interaction,
    moderator_role: discord.Role,
    log_channel: discord.TextChannel
):
    if not interaction.guild or not interaction.user.guild_permissions.manage_guild:
        return await interaction.response.send_message("You need **Manage Server**.", ephemeral=True)

    c = guild_cfg(interaction.guild.id)
    c["moderator_role_id"] = moderator_role.id
    c["log_channel_id"] = log_channel.id
    save_json(CONFIG_FILE, config)

    await interaction.response.send_message(
        f"🌸 **Airi Innocent is watching now.**\n\n"
        f"Moderator role: {moderator_role.mention}\n"
        f"Log channel: {log_channel.mention}\n\n"
        "Automatic spam, weird-message, advertising, scam, and high-confidence harassment detection is enabled.",
        ephemeral=True
    )

@bot.tree.command(name="innocent-toggle", description="Turn automatic monitoring on or off.")
async def innocent_toggle(interaction: discord.Interaction, enabled: bool):
    if not interaction.guild or not interaction.user.guild_permissions.manage_guild:
        return await interaction.response.send_message("You need **Manage Server**.", ephemeral=True)

    guild_cfg(interaction.guild.id)["enabled"] = enabled
    save_json(CONFIG_FILE, config)

    await interaction.response.send_message(
        f"🌸 Automatic monitoring is **{'ON' if enabled else 'OFF'}**.",
        ephemeral=True
    )

@bot.tree.command(name="weird-detection", description="Toggle aggressive weird/disruptive message detection.")
async def weird_detection(interaction: discord.Interaction, enabled: bool):
    if not interaction.guild or not interaction.user.guild_permissions.manage_guild:
        return await interaction.response.send_message("You need **Manage Server**.", ephemeral=True)

    guild_cfg(interaction.guild.id)["weird_message_detection"] = enabled
    save_json(CONFIG_FILE, config)

    await interaction.response.send_message(
        f"🌸 Weird/disruptive message detection is **{'ON' if enabled else 'OFF'}**.",
        ephemeral=True
    )

@bot.tree.command(name="privacy-alerts", description="Toggle possible privacy-information alerts.")
async def privacy_alerts(interaction: discord.Interaction, enabled: bool):
    if not interaction.guild or not interaction.user.guild_permissions.manage_guild:
        return await interaction.response.send_message("You need **Manage Server**.", ephemeral=True)

    guild_cfg(interaction.guild.id)["privacy_alerts"] = enabled
    save_json(CONFIG_FILE, config)

    await interaction.response.send_message(
        f"🌸 Privacy alerts are **{'ON' if enabled else 'OFF'}**.",
        ephemeral=True
    )

@bot.tree.command(name="innocent-history", description="View a member's recent Airi Innocent alerts.")
async def innocent_history(interaction: discord.Interaction, member: discord.Member):
    if not isinstance(interaction.user, discord.Member) or not is_staff(interaction.user):
        return await interaction.response.send_message("This command is for staff.", ephemeral=True)

    entries = [
        x for x in history
        if x.get("guild_id") == interaction.guild.id and x.get("user_id") == member.id
    ][-10:]

    if not entries:
        return await interaction.response.send_message("No alerts saved for that member.", ephemeral=True)

    embed = discord.Embed(
        title=f"🌸 Innocent History — {member.display_name}",
        color=discord.Color.from_rgb(255, 182, 193)
    )

    for item in reversed(entries):
        embed.add_field(
            name=f"Rule {item['rule']} — {RULES.get(item['rule'], 'Unknown')}",
            value=(
                f"{item['reason'][:700]}\n"
                f"**Source:** {item['source']}\n"
                f"**UTC:** {item['timestamp'][:19].replace('T', ' ')}"
            ),
            inline=False
        )

    await interaction.response.send_message(embed=embed, ephemeral=True)

def get_custom_status(member):
    for activity in member.activities:
        if isinstance(activity, discord.CustomActivity):
            return getattr(activity, "state", None) or (
                activity.name if activity.name != "Custom Status" else None
            )
    return None

@bot.tree.command(name="sync-profile", description="Sync Airi Innocent's profile with the owner.")
async def sync_profile(interaction: discord.Interaction):
    if OWNER_USER_ID == 0:
        return await interaction.response.send_message("Set `OWNER_USER_ID` first.", ephemeral=True)

    if interaction.user.id != OWNER_USER_ID:
        return await interaction.response.send_message("Only the owner can use this.", ephemeral=True)

    await interaction.response.defer(ephemeral=True)

    try:
        owner = await bot.fetch_user(OWNER_USER_ID)
    except Exception:
        return await interaction.followup.send("I couldn't fetch your profile.", ephemeral=True)

    changed = []

    try:
        avatar = await owner.display_avatar.read()
        if bot.user.avatar != owner.avatar:
            await bot.user.edit(avatar=avatar)
            changed.append("avatar")
    except Exception:
        pass

    try:
        if owner.banner:
            banner = await owner.banner.read()
            await bot.user.edit(banner=banner)
            changed.append("banner")
    except Exception:
        pass

    for guild in bot.guilds:
        member = guild.get_member(OWNER_USER_ID)
        if not member:
            continue

        try:
            if guild.me and guild.me.nick != member.display_name:
                await guild.me.edit(nick=member.display_name[:32], reason="Owner profile sync")
                changed.append("server nickname")
        except Exception:
            pass

        status = get_custom_status(member)
        if status:
            try:
                await bot.change_presence(activity=discord.Game(name=status[:128]))
                changed.append("thought/status")
            except Exception:
                pass
        break

    if changed:
        await interaction.followup.send(
            "🌸 Synced: **" + ", ".join(dict.fromkeys(changed)) + "**.",
            ephemeral=True
        )
    else:
        await interaction.followup.send(
            "🌸 Nothing needed changing, or Discord blocked the edit.",
            ephemeral=True
        )

@bot.event
async def on_ready():
    print(f"Airi Innocent is online as {bot.user}!")
    print("Automatic rule patrol is active 🌸")

token = os.getenv("DISCORD_TOKEN")

if not token:
    print("ERROR: DISCORD_TOKEN is missing.")
else:
    bot.run(token)
