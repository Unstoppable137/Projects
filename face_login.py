#!/usr/bin/env python3
import face_recognition, cv2, os, sys
KNOWN_DIR = 'faces'

def load_known():
    encs, names = [], []
    if not os.path.exists(KNOWN_DIR):
        print('No faces registered.')
        return encs, names
    for f in os.listdir(KNOWN_DIR):
        if f.lower().endswith(('.jpg','.png','.jpeg')):
            path = os.path.join(KNOWN_DIR, f)
            img = face_recognition.load_image_file(path)
            locs = face_recognition.face_locations(img)
            if not locs:
                continue
            enc = face_recognition.face_encodings(img, known_face_locations=locs)[0]
            encs.append(enc)
            names.append(os.path.splitext(f)[0])
    return encs, names

def authenticate(tol=0.5):
    encs, names = load_known()
    if not encs:
        print('No known faces found. Register first.')
        return None
    cam = cv2.VideoCapture(0)
    if not cam.isOpened():
        print('Camera error.')
        return None
    print('Looking for face. Press q to cancel.')
    user = None
    while True:
        ret, frame = cam.read()
        if not ret:
            break
        rgb = frame[:, :, ::-1]
        small = cv2.resize(rgb, (0,0), fx=0.5, fy=0.5)
        locs = face_recognition.face_locations(small)
        encs_now = face_recognition.face_encodings(small, locs)
        for e in encs_now:
            res = face_recognition.compare_faces(encs, e, tolerance=tol)
            if True in res:
                idx = res.index(True)
                user = names[idx]
                print('Authenticated as', user)
                cam.release()
                cv2.destroyAllWindows()
                return user
        cv2.imshow('Authenticate - press q to cancel', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
    cam.release()
    cv2.destroyAllWindows()
    return None

if __name__ == '__main__':
    u = authenticate()
    if u:
        print('SUCCESS', u)
    else:
        print('FAILED')