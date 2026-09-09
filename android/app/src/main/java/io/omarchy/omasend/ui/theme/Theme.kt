package io.omarchy.omasend.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

private val DarkColorScheme = darkColorScheme(
    primary = OmarchyCyan,
    onPrimary = OmarchyDarkBg,
    primaryContainer = OmarchyCyanDark,
    onPrimaryContainer = OmarchyCyanLight,
    secondary = OmarchyBlue,
    onSecondary = OmarchyDarkBg,
    secondaryContainer = OmarchyBlueDark,
    onSecondaryContainer = OmarchyBlueLight,
    background = OmarchyDarkBg,
    onBackground = OmarchyTextPrimary,
    surface = OmarchySurface,
    onSurface = OmarchyTextPrimary,
    surfaceVariant = OmarchySurfaceContainer,
    onSurfaceVariant = OmarchyTextSecondary,
    surfaceContainer = OmarchySurfaceContainer,
    surfaceContainerHigh = OmarchySurfaceContainerHigh,
    outline = OmarchyBorder,
    outlineVariant = OmarchyBorderSubtle,
    error = OmarchyRed,
    errorContainer = OmarchyRedContainer
)

private val LightColorScheme = lightColorScheme(
    primary = OmarchyLightPrimary,
    onPrimary = OmarchyLightOnPrimary,
    primaryContainer = OmarchyLightPrimaryContainer,
    onPrimaryContainer = OmarchyLightOnPrimaryContainer,
    secondary = OmarchyLightSecondary,
    onSecondary = OmarchyLightOnSecondary,
    secondaryContainer = OmarchyLightSecondaryContainer,
    onSecondaryContainer = OmarchyLightOnSecondaryContainer,
    background = OmarchyLightBg,
    onBackground = OmarchyLightTextPrimary,
    surface = OmarchyLightSurface,
    onSurface = OmarchyLightTextPrimary,
    surfaceVariant = OmarchyLightSurfaceContainer,
    onSurfaceVariant = OmarchyLightTextSecondary,
    surfaceContainer = OmarchyLightSurfaceContainer,
    surfaceContainerHigh = OmarchyLightSurfaceContainerHigh,
    outline = OmarchyLightBorder,
    outlineVariant = OmarchyLightBorderSubtle,
    error = OmarchyRed
)

@Composable
fun OmaSendTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}

