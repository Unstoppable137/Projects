#!/usr/bin/env python3
import cv2, os
KNOWN_DIR = "faces"
os.makedirs(KNOWN_DIR, exist_ok=True)

def register_face(name):
    cam = cv2.VideoCapture(0)
    if not cam.isOpened():
        print('ERROR: Could not open webcam. Check permissions.')
        return
    print('Press s to save a frame, q to quit.')
    while True:
        ret, frame = cam.read()
        if not ret:
            print('Failed to read from camera.')
            break
        cv2.imshow('Register Face - press s to save', frame)
        key = cv2.waitKey(1) & 0xFF
        if key == ord('s'):
            path = os.path.join(KNOWN_DIR, f"{name}.jpg")
            cv2.imwrite(path, frame)
            print('Saved', path)
            break
        elif key == ord('q'):
            break
    cam.release()
    cv2.destroyAllWindows()

if __name__ == '__main__':
    name = input('Enter username (no spaces): ').strip()
    if name:
        register_face(name)
    else:
        print('Invalid name.')
