package io.omarchy.omasend.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = OmarchyCyan,
    onPrimary = OmarchyDarkBg,
    secondary = OmarchyBlue,
    onSecondary = OmarchyDarkBg,
    background = OmarchyDarkBg,
    onBackground = OmarchyTextPrimary,
    surface = OmarchyCardBg,
    onSurface = OmarchyTextPrimary,
    surfaceVariant = OmarchyBorder,
    onSurfaceVariant = OmarchyTextSecondary,
    error = OmarchyRed
)

@Composable
fun OmaSendTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}
