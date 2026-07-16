import cv2
import numpy as np
import os
from database.db_manager import update_asset_status

def compute_visual_variance(baseline_path, current_path):
    """
    Compares two images using OpenCV structural difference.
    Returns (variance_score_percentage, diff_image_path)
    """
    try:
        base_img = cv2.imread(baseline_path, cv2.IMREAD_GRAYSCALE)
        curr_img = cv2.imread(current_path, cv2.IMREAD_GRAYSCALE)
        
        if base_img is None or curr_img is None:
            return 0.0, None
            
        # Ensure identical sizes for comparison by resizing current to baseline
        if base_img.shape != curr_img.shape:
            curr_img = cv2.resize(curr_img, (base_img.shape[1], base_img.shape[0]))
            
        # Absolute difference between images
        diff = cv2.absdiff(base_img, curr_img)
        
        # Threshold difference to ignore minor anti-aliasing / rendering shifts
        # 30 out of 255 is a conservative threshold
        _, thresh = cv2.threshold(diff, 30, 255, cv2.THRESH_BINARY)
        
        # Calculate percentage of pixels that have changed
        non_zero_count = np.count_nonzero(thresh)
        total_pixels = base_img.size
        variance_score = (non_zero_count / total_pixels) * 100
        
        # Create a visual diff map (red highlights over the baseline image)
        diff_overlay = cv2.cvtColor(base_img, cv2.COLOR_GRAY2BGR)
        diff_overlay[thresh == 255] = [0, 0, 255] # Red highlights for changed pixels
        
        diff_path = current_path.replace('current_', 'diff_')
        cv2.imwrite(diff_path, diff_overlay)
        
        return variance_score, diff_path
    except Exception as e:
        print(f"Visual comparison error: {e}")
        return 0.0, None

def run_defacement_check(asset_id, baseline_path, current_path):
    """
    Executes the visual defacement check and updates database if CRITICAL.
    Threshold: 1.0% variance.
    """
    variance_score, diff_path = compute_visual_variance(baseline_path, current_path)
    
    # 1.0% variance is our defacement threshold (since pixel lines are thin but visible)
    is_defaced = variance_score > 1.0
    
    if is_defaced:
        update_asset_status(asset_id, 'CRITICAL / DEFACED')
    else:
        # If it was previously defaced but is now fixed
        update_asset_status(asset_id, 'Monitored')
        
    return variance_score, is_defaced, diff_path
