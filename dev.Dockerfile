FROM initc3/linux-sgx:2.13.3-ubuntu20.04 AS dev

RUN apt-get update && apt-get install -y \
                autotools-dev \
                automake \
                xxd \
                iputils-ping \
                libssl-dev \
                vim \
                git \
                texinfo \
        && rm -rf /var/lib/apt/lists/*


ENV SGX_SDK /opt/sgxsdk
ENV PATH $PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
ENV PKG_CONFIG_PATH $SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH $SGX_SDK/sdk_libs

# installing sgx-gmp library
RUN cd /tmp;\
git clone https://github.com/intel/sgx-gmp.git;\
cd sgx-gmp;\
./configure --prefix=/opt/gmp/6.1.2 --enable-assembly --disable-shared --enable-static --with-pic; \
make -j; \
make install; \
./sgx-configure; \
make -j; \
make install

WORKDIR /usr/src/sgxvoting

# COPY . .

ARG SGX_MODE=HW
ENV SGX_MODE $SGX_MODE

ARG SGX_DEBUG=1
ENV SGX_DEBUG $SGX_DEBUG

# RUN make