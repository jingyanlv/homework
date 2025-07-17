#include <opencv2/opencv.hpp>
#include <iostream>
#include <vector>
#include <cmath>

using namespace cv;
using namespace std;

Mat embedWatermark(const Mat& host, const Mat& watermark, double alpha = 0.1) {
    
    Mat yuv;
    cvtColor(host, yuv, COLOR_BGR2YUV);

    vector<Mat> channels;
    split(yuv, channels);
    Mat Y = channels[0].clone();

   
    Mat wm;
    resize(watermark, wm, Size(host.cols / 8, host.rows / 8));
    threshold(wm, wm, 128, 1, THRESH_BINARY);

    
    Mat watermarkedY = Mat::zeros(Y.size(), CV_32F);
    for (int i = 0; i < Y.rows; i += 8) {
        for (int j = 0; j < Y.cols; j += 8) {
        
            Rect blockRect(j, i, 8, 8);
            if (blockRect.br().x > Y.cols || blockRect.br().y > Y.rows)
                continue;

            Mat block = Y(blockRect).clone();
            block.convertTo(block, CV_32F);

            
            Mat dctBlock;
            dct(block, dctBlock);

         
            int wm_i = i / 8;
            int wm_j = j / 8;
            int wm_val = 0;

            if (wm_i < wm.rows && wm_j < wm.cols) {
                wm_val = wm.at<uchar>(wm_i, wm_j);
            }

           
            double coeff1 = dctBlock.at<float>(3, 4);
            double coeff2 = dctBlock.at<float>(4, 3);

            if (wm_val) {
                dctBlock.at<float>(3, 4) = coeff1 * (1 + alpha);
                dctBlock.at<float>(4, 3) = coeff2 * (1 + alpha);
            }
            else {
                dctBlock.at<float>(3, 4) = coeff1 * (1 - alpha);
                dctBlock.at<float>(4, 3) = coeff2 * (1 - alpha);
            }

            
            Mat idctBlock;
            idct(dctBlock, idctBlock);

      
            idctBlock.convertTo(idctBlock, CV_8U);
            idctBlock.copyTo(watermarkedY(blockRect));
        }
    }


    channels[0] = watermarkedY;
    Mat result;
    merge(channels, result);
    cvtColor(result, result, COLOR_YUV2BGR);

    return result;
}


Mat extractWatermark(const Mat& watermarked, Size wmSize, double alpha = 0.1) {
    Mat yuv;
    cvtColor(watermarked, yuv, COLOR_BGR2YUV);

    vector<Mat> channels;
    split(yuv, channels);
    Mat Y = channels[0].clone();

  
    Mat extracted = Mat::zeros(wmSize, CV_8U);

   
    for (int i = 0; i < Y.rows; i += 8) {
        for (int j = 0; j < Y.cols; j += 8) {
            Rect blockRect(j, i, 8, 8);
            if (blockRect.br().x > Y.cols || blockRect.br().y > Y.rows)
                continue;

            Mat block = Y(blockRect).clone();
            block.convertTo(block, CV_32F);

        
            Mat dctBlock;
            dct(block, dctBlock);

            int wm_i = i / 8;
            int wm_j = j / 8;

            if (wm_i >= wmSize.height || wm_j >= wmSize.width)
                continue;

           
            double coeff1 = dctBlock.at<float>(3, 4);
            double coeff2 = dctBlock.at<float>(4, 3);

            double avg = (coeff1 + coeff2) / 2.0;
            double diff = abs(coeff1 - coeff2);

       
            if (diff > alpha * avg) {
                extracted.at<uchar>(wm_i, wm_j) = (coeff1 > coeff2) ? 255 : 0;
            }
        }
    }

    return extracted;
}


void robustnessTest(Mat& watermarked, const Mat& origWatermark) {
    vector<pair<string, Mat>> attacks;


    Mat rotated;
    Point2f center(watermarked.cols / 2.0, watermarked.rows / 2.0);
    Mat rotMat = getRotationMatrix2D(center, 15, 1.0);
    warpAffine(watermarked, rotated, rotMat, watermarked.size());
    attacks.push_back({ "Rotation", rotated });

    
    Rect cropRect(watermarked.cols / 4, watermarked.rows / 4,
        watermarked.cols / 2, watermarked.rows / 2);
    Mat cropped = watermarked(cropRect).clone();
    attacks.push_back({ "Cropping", cropped });

  
    Mat contrast;
    watermarked.convertTo(contrast, -1, 1.5, 0);
    attacks.push_back({ "Contrast", contrast });

   
    Mat noisy = watermarked.clone();
    Mat noise(noisy.size(), noisy.type());
    randn(noise, 0, 25);
    noisy += noise;
    attacks.push_back({ "Gaussian Noise", noisy });

   
    vector<uchar> jpegBuf;
    vector<int> params = { IMWRITE_JPEG_QUALITY, 70 };
    imencode(".jpg", watermarked, jpegBuf, params);
    Mat jpeg = imdecode(jpegBuf, IMREAD_COLOR);
    attacks.push_back({ "JPEG Compression", jpeg });

    
    for (auto& [name, attacked] : attacks) {
        Mat extracted = extractWatermark(
            attacked,
            Size(origWatermark.cols / 8, origWatermark.rows / 8)
        );

        double nc = 0;
        int count = 0;
        for (int i = 0; i < extracted.rows; i++) {
            for (int j = 0; j < extracted.cols; j++) {
                if (extracted.at<uchar>(i, j) == 255 &&
                    origWatermark.at<uchar>(i, j) == 255) {
                    nc++;
                }
                if (origWatermark.at<uchar>(i, j) == 255) {
                    count++;
                }
            }
        }
        nc = (count > 0) ? nc / count : 0;

        cout << "Attack: " << name
            << " | NC: " << nc
            << " | Similarity: " << (nc * 100) << "%" << endl;

    
        resize(extracted, extracted, origWatermark.size());
        imshow(name + " Attack", attacked);
        imshow("Extracted from " + name, extracted);
    }
}

int main() {
   
    Mat host = imread("host.jpg");
    Mat watermark = imread("watermark.png", IMREAD_GRAYSCALE);

    if (host.empty() || watermark.empty()) {
        cerr << "Error loading images!" << endl;
        return -1;
    }


    Mat watermarked = embedWatermark(host, watermark, 0.15);
    imwrite("watermarked.jpg", watermarked);

   
    Mat extracted = extractWatermark(
        watermarked,
        Size(watermark.cols / 8, watermark.rows / 8)
    );
    resize(extracted, extracted, watermark.size());
    imwrite("extracted.png", extracted);


    robustnessTest(watermarked, watermark);

    
    imshow("Original Host", host);
    imshow("Original Watermark", watermark);
    imshow("Watermarked Image", watermarked);
    imshow("Extracted Watermark", extracted);

    waitKey(0);
    return 0;
}