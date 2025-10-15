from setuptools import setup, find_packages

setup(
    name='iris-misp-pusher',
    python_requires='>=3.9',
    version='0.1.0',
    # find_packages() sẽ tự động tìm các package cần thiết
    packages=find_packages(),
    url='https://github.com/wanthinnn/iris-misp-pusher',
    license='MIT',
    author='wanthinnn', # Sửa lại tên tác giả
    author_email='thienlai159@gmail.com',
    description='An IRIS processor module to push case IOCs to a MISP instance.',
    install_requires=[], # Nếu module của bạn cần thư viện nào, hãy thêm vào đây, ví dụ: ['requests']

    # =====================================================================
    # PHẦN QUAN TRỌNG NHẤT BỊ THIẾU LÀ ĐÂY
    # Nó "đăng ký" module của bạn với IRIS
    # =====================================================================
    entry_points='''
        [iris_modules]
        MISP_Pusher=iris_misp_pusher.IrisMispInterface:IrisMispInterface
    '''
)



# setup(
#     name='iris-misp-pusher',
#     python_requires='>=3.9',
#     version='0.1.0',
#     packages=['iris_misp_pusher', 'iris_misp_pusher.misp_handler'],
#     url='https://github.com/wanthinnn/iris-misp-pusher',
#     license='MIT',
#     author='iris-misp-pusher',
#     author_email='thienlai159@gmail.com',
#     description='`iris-misp-pusher` is a IRIS pipeline/processor module created with https://github.com/dfir-iris/iris-skeleton-module',
#     install_requires=[]
# )
