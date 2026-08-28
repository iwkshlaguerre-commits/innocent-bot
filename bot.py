import discord
from discord import app_commands
import os


# ============================================================
# BOT SETUP
# ============================================================

class OfficeAfterDarkBot(discord.Client):

    def __init__(self):

        intents = discord.Intents.default()

        super().__init__(
            intents=intents
        )

        self.tree = app_commands.CommandTree(self)


    async def setup_hook(self):

        # Register slash commands
        synced = await self.tree.sync()

        print(
            f"Synced {len(synced)} command(s)! 🌸"
        )


bot = OfficeAfterDarkBot()


# ============================================================
# HEX COLOR
# ============================================================

def hex_to_color(hex_code):

    hex_code = hex_code.strip().replace("#", "")

    if len(hex_code) != 6:
        raise ValueError

    try:

        return discord.Color(
            int(hex_code, 16)
        )

    except ValueError:

        raise ValueError


# ============================================================
# EMBED FORM
# ============================================================

class EmbedCreateModal(
    discord.ui.Modal,
    title="🌸 Create an Embed"
):

    embed_name = discord.ui.TextInput(
        label="Embed Name",
        placeholder="Example: server-rules",
        required=True,
        max_length=100
    )

    embed_title = discord.ui.TextInput(
        label="Embed Title",
        placeholder="Example: Server Rules",
        required=True,
        max_length=256
    )

    description = discord.ui.TextInput(
        label="Description",
        placeholder=(
            "Write your embed here!\n\n"
            "You can make paragraphs and blank lines."
        ),
        style=discord.TextStyle.paragraph,
        required=True,
        max_length=4000
    )

    image_url = discord.ui.TextInput(
        label="Image / GIF URL",
        placeholder="Optional — https://...",
        required=False,
        max_length=1000
    )

    color_hex = discord.ui.TextInput(
        label="HEX Color",
        placeholder="#FFB6C1",
        default="#FFB6C1",
        required=True,
        max_length=7
    )


    def __init__(
        self,
        target_channel
    ):

        super().__init__()

        self.target_channel = target_channel


    async def on_submit(
        self,
        interaction: discord.Interaction
    ):

        # --------------------------------------------
        # CONVERT HEX COLOR
        # --------------------------------------------

        try:

            color = hex_to_color(
                self.color_hex.value
            )

        except ValueError:

            await interaction.response.send_message(
                "❌ That isn't a valid HEX color!\n\n"
                "Use something like `#FFB6C1`.",
                ephemeral=True
            )

            return


        # --------------------------------------------
        # CREATE EMBED
        # --------------------------------------------

        embed = discord.Embed(
            title=self.embed_title.value,
            description=self.description.value,
            color=color
        )


        # --------------------------------------------
        # OPTIONAL IMAGE / GIF
        # --------------------------------------------

        image = self.image_url.value.strip()

        if image:

            embed.set_image(
                url=image
            )


        # --------------------------------------------
        # FOOTER
        # --------------------------------------------

        embed.set_footer(
            text="Office After Dark"
        )


        # --------------------------------------------
        # SEND EMBED
        # --------------------------------------------

        try:

            await self.target_channel.send(
                embed=embed
            )

        except discord.Forbidden:

            await interaction.response.send_message(
                "❌ I don't have permission to send "
                "embeds in this channel.",
                ephemeral=True
            )

            return


        # --------------------------------------------
        # CONFIRMATION
        # --------------------------------------------

        await interaction.response.send_message(
            "🌸 Your embed has been created!",
            ephemeral=True
        )


# ============================================================
# /EMBED-CREATE
# ============================================================

@bot.tree.command(
    name="embed-create",
    description="Create an embed in the current channel."
)
async def embed_create(
    interaction: discord.Interaction
):

    # Must be used inside a server
    if interaction.guild is None:

        await interaction.response.send_message(
            "❌ This command can only be used in a server.",
            ephemeral=True
        )

        return


    # Only staff with Manage Server
    if not interaction.user.guild_permissions.manage_guild:

        await interaction.response.send_message(
            "❌ You need **Manage Server** permission "
            "to create embeds.",
            ephemeral=True
        )

        return


    # Make sure we're in a text channel
    if not isinstance(
        interaction.channel,
        discord.TextChannel
    ):

        await interaction.response.send_message(
            "❌ Use this command inside a text channel.",
            ephemeral=True
        )

        return


    # Open the form IMMEDIATELY
    await interaction.response.send_modal(
        EmbedCreateModal(
            interaction.channel
        )
    )


# ============================================================
# READY
# ============================================================

@bot.event
async def on_ready():

    print(
        "================================"
    )

    print(
        f"Office After Dark is online as {bot.user}!"
    )

    print(
        "Try /embed-create in Discord."
    )

    print(
        "================================"
    )


# ============================================================
# START BOT
# ============================================================

token = os.getenv(
    "DISCORD_TOKEN"
)

if not token:

    print(
        "ERROR: DISCORD_TOKEN is not set!"
    )

else:

    bot.run(
        token
    )