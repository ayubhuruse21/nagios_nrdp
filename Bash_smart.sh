#!/bin/bash

# Default values
path="/"
warning_threshold=85

# Parse command line arguments
while [[ "$1" != "" ]]; do
    case $1 in
        -p | --path) shift; path=$1 ;;
        -w | --warning) shift; warning_threshold=$1 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# Function to get disk usage in GB (Linux)
get_disk_usage_linux() {
    disk_info=$(df -B 1G "$path" | tail -n 1)
    total=$(echo $disk_info | awk '{print $2}')
    used=$(echo $disk_info | awk '{print $3}')
    available=$(echo $disk_info | awk '{print $4}')
    used_percent=$(echo $disk_info | awk '{print $5}' | sed 's/%//')

    echo "$total $used $available $used_percent"
}

# Function to get disk usage in GB (Windows using WMIC or PowerShell)
get_disk_usage_windows() {
    if command -v wmic > /dev/null 2>&1; then
        disk_info=$(wmic logicaldisk where "DeviceID='$path'" get size,freespace,caption)
        total=$(echo "$disk_info" | awk 'NR==2 {print $1 / 1073741824}')  # Convert bytes to GB
        used=$(echo "$disk_info" | awk 'NR==2 {print ($1 - $2) / 1073741824}')
        free=$(echo "$disk_info" | awk 'NR==2 {print $2 / 1073741824}')
        used_percent=$(echo "scale=2; ($used / $total) * 100" | bc)
    else
        # PowerShell method if wmic is unavailable
        disk_info=$(powershell -Command "Get-PSDrive -Name $path | Select-Object Used, @{Name='Total';Expression={\$_.Used + \$_.Free}}, @{Name='Free';Expression={\$_.Free}}")
        total=$(echo "$disk_info" | awk '{print $2 / 1073741824}')  # GB conversion
        used=$(echo "$disk_info" | awk '{print $1 / 1073741824}')
        free=$(echo "$disk_info" | awk '{print $3 / 1073741824}')
        used_percent=$(echo "scale=2; ($used / $total) * 100" | bc)
    fi

    echo "$total $used $free $used_percent"
}

# Check platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux-specific disk usage
    read total used free used_percent < <(get_disk_usage_linux)
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    # Windows-specific disk usage
    read total used free used_percent < <(get_disk_usage_windows)
else
    echo "Unsupported OS"
    exit 1
fi

# Function to predict disk fill time
predict_disk_fill() {
    usage_delta=0.5  # Mock growth rate (percentage per hour)
    check_interval=1  # Mock check interval in hours

    if (( $(echo "$usage_delta <= 0" | bc -l) )); then
        echo "Not growing"
        return
    fi

    hours_to_fill=$(echo "($((100 - used_percent)) / $usage_delta) * $check_interval" | bc)
    days=$(echo "$hours_to_fill / 24" | bc)
    hours=$(echo "$hours_to_fill % 24" | bc)

    echo "$days days and $hours hours"
}

# Get fill prediction
fill_prediction=$(predict_disk_fill)

# Determine status
if (( $(echo "$used_percent < $warning_threshold" | bc -l) )); then
    status_message="OK - $used_percent% of disk space used. Total: $total GB, Used: $used GB, Free: $free GB. Estimated time to full: $fill_prediction"
    echo "$status_message"
    exit 0
elif (( $(echo "$used_percent < 95" | bc -l) )); then
    status_message="WARNING - $used_percent% of disk space used. Total: $total GB, Used: $used GB, Free: $free GB. Estimated time to full: $fill_prediction"
    echo "$status_message"
    exit 1
else
    status_message="CRITICAL - $used_percent% of disk space used. Total: $total GB, Used: $used GB, Free: $free GB. Estimated time to full: $fill_prediction"
    echo "$status_message"
    exit 2
fi
