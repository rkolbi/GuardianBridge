@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM Rewrites local history to a single commit based on branch 1.4, then force-pushes.
REM Run this from anywhere; script will cd to repo root (one level above this script).

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%.."
if errorlevel 1 (
  echo [ERROR] Could not change to repository root.
  exit /b 1
)

set "TARGET_BRANCH=1.4"
set "CLEAN_BRANCH=clean-1.4"
set "REMOTE=origin"
set "PREP_COMMIT_MSG=Prepare clean public snapshot"
set "ROOT_COMMIT_MSG=GuardianBridge 1.4 initial public release"

echo.
echo ============================================================================
echo WARNING: This script rewrites git history and force-pushes branch %TARGET_BRANCH%.
echo It is destructive for history.
echo ============================================================================
echo.
set /p CONFIRM=Type YES to continue: 
if /I not "%CONFIRM%"=="YES" goto :cancel

where git >nul 2>&1
if errorlevel 1 (
  echo [ERROR] git is not available in PATH.
  goto :error
)

git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Current folder is not a git repository.
  goto :error
)

echo [INFO] Fetching remote refs...
git fetch %REMOTE% --prune
if errorlevel 1 goto :error

echo [INFO] Checking out %TARGET_BRANCH%...
git checkout %TARGET_BRANCH%
if errorlevel 1 goto :error

echo [INFO] Pulling latest %TARGET_BRANCH% from %REMOTE%...
git pull %REMOTE% %TARGET_BRANCH%
if errorlevel 1 goto :error

echo [INFO] Removing private/runtime paths from tracking...
for %%P in (.env data mock releases AutoBackUp) do (
  git rm -r --cached --ignore-unmatch "%%P" >nul 2>&1
)

echo [INFO] Staging files...
git add -A
if errorlevel 1 goto :error
if exist ".gitignore" git add ".gitignore"
if exist ".env.example" git add ".env.example"

git diff --cached --quiet
if errorlevel 1 (
  echo [INFO] Creating prep commit...
  git commit -m "%PREP_COMMIT_MSG%"
  if errorlevel 1 goto :error
) else (
  echo [INFO] No prep changes to commit.
)

echo [INFO] Creating orphan branch %CLEAN_BRANCH%...
git checkout --orphan %CLEAN_BRANCH%
if errorlevel 1 goto :error

git add -A
if errorlevel 1 goto :error

echo [INFO] Creating single fresh commit...
git commit -m "%ROOT_COMMIT_MSG%"
if errorlevel 1 goto :error

echo [INFO] Replacing local branch %TARGET_BRANCH%...
git branch -D %TARGET_BRANCH% >nul 2>&1
git branch -m %TARGET_BRANCH%
if errorlevel 1 goto :error

echo [INFO] Force-pushing %TARGET_BRANCH% to %REMOTE%...
git push -f %REMOTE% %TARGET_BRANCH%
if errorlevel 1 goto :error

call :ask_yes_no "Delete remote main/master branches if they exist? [y/N]: " DELETE_OLD_BRANCHES
if /I "!DELETE_OLD_BRANCHES!"=="YES" (
  if /I not "%TARGET_BRANCH%"=="main" git push %REMOTE% --delete main >nul 2>&1
  if /I not "%TARGET_BRANCH%"=="master" git push %REMOTE% --delete master >nul 2>&1
)

call :ask_yes_no "Delete all local+remote tags? [y/N]: " DELETE_TAGS
if /I "!DELETE_TAGS!"=="YES" (
  for /f "delims=" %%T in ('git tag -l') do (
    git push %REMOTE% ":refs/tags/%%T" >nul 2>&1
    git tag -d "%%T" >nul 2>&1
  )
)

echo.
echo [DONE] History rewrite completed for %TARGET_BRANCH%.
echo [ACTION] Rotate any credentials that may have been exposed previously.
popd
exit /b 0

:ask_yes_no
set "%~2=NO"
set "ANSWER="
set /p ANSWER=%~1
if /I "%ANSWER%"=="Y" set "%~2=YES"
if /I "%ANSWER%"=="YES" set "%~2=YES"
exit /b 0

:cancel
echo [CANCELLED] No changes were made.
popd
exit /b 0

:error
echo.
echo [FAILED] Script stopped due to an error. Review output above.
popd
exit /b 1
