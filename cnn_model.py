#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on 2019-12-18

@author: mingo
@module: experiment_mama.cnn_model
'''

import torch
import torch.nn as nn
import numpy as np

class ConvLayer(torch.nn.Module):
    def __init__(self, kernel_size, in_channel, out_channel):
        super(ConvLayer, self).__init__()
        
        self.conv = nn.Conv2d(in_channels=in_channel, out_channels=out_channel, kernel_size=kernel_size, stride=1, padding=0)
        self.pool = nn.MaxPool2d(kernel_size=kernel_size)
        
    def forward(self, x):
        h = self.conv(x)
        h = torch.relu(h)
        h = self.pool(h)
        return h
    
class ConvNet2D(torch.nn.Module):
    def __init__(self, layer_num, kernel_size):
        super(ConvNet2D, self).__init__()
        
        self.layer_num = layer_num
        self.kernel_size = kernel_size
        
        channels = 1
        for i in range(layer_num):
            conv = ConvLayer(kernel_size, channels, channels * 4)
            setattr(self, 'conv_%d' % (i+1), conv)
            channels *= 4
        
        self.fc = nn.Linear(channels, 1)
    
    def forward(self, x):
        # (B, N, N) -> (B, 1, N, N)
        h = torch.unsqueeze(x, 1)

        
        for i in range(self.layer_num):
            # (B, c_in, N_in, N_in) -> (B, c_out, N_out, N_out)
            conv = getattr(self, 'conv_%d'%(i+1))
            h = conv(h)
        
        _, _, n, _ = list(h.size())
        
        # (B, c_out, N_out, N_out) -> (B, c_out, 1, 1)
        pool = nn.MaxPool2d(kernel_size=n)
        h = pool(h)
        
        # (B, c_out, 1, 1) -> (B, c_out)
        h = torch.squeeze(h)
        
        # (B, c_out) -> (B, 1)
        h = self.fc(h)
        
        # (B, 1) -> (B, 1)
        h = torch.sigmoid(h)
        
        # (B, 1) -> (B)
        h = torch.squeeze(h)
        
        return h
    
class CNN():
    def __init__(self, layer_num=3, kernel_size=5, gpu_id=1):
        self.gpu_id = gpu_id
        self.model = ConvNet2D(layer_num, kernel_size).cuda(gpu_id)
        self.loss = torch.nn.BCELoss()
        
    def next_train_batch(self, x, y, batch_size):
        n = y.size
        rand_idx = np.random.permutation(n)
        
        if n % batch_size == 0:
            batch_len = n // batch_size
        else:
            batch_len = n // batch_size + 1
        
        start = 0
        for i in range(batch_len):
            end = min(start + batch_size, n)
            yield x[rand_idx[start:end], :, :], y[rand_idx[start:end]]
            start = end
            
    def next_pred_batch(self, x, batch_size):
        n, _, _ = x.shape
        
        if n % batch_size == 0:
            batch_len = n // batch_size
        else:
            batch_len = n // batch_size + 1
        
        start = 0
        for i in range(batch_len):
            end = min(start + batch_size, n)
            yield x[start:end, :, :]
            start = end
        
    
    def update(self, x, y, batch_size):
        epoch_loss = 0
        epoch_len = 0
        
        for batch_x, batch_y in self.next_train_batch(x, y, batch_size):
            batch_x_tensor = torch.FloatTensor(batch_x).cuda(self.gpu_id)
            batch_y_tensor = torch.FloatTensor(batch_y).cuda(self.gpu_id)
            
            batch_x_tensor.requires_grad = False
            batch_y_tensor.requires_grad = False
            
            self.optimizer.zero_grad()
            self.model.train()
    
            batch_pred_tensor = self.model.forward(batch_x_tensor)
            loss = self.loss(batch_pred_tensor, batch_y_tensor)
            
            loss.backward()
            self.optimizer.step()
            
            epoch_loss += loss.item()
            epoch_len += y.size
        
        epoch_loss /= epoch_len
        return epoch_loss
            
    
    def fit(self, x, y, epoch=10, batch_size=500, lr=0.01):
        parameters = filter(lambda p: p.requires_grad, self.model.parameters())
        self.optimizer = torch.optim.Adam(parameters, lr) 
        
        for e in range(epoch):
            epoch_loss = self.update(x, y, batch_size)
            print('\tepoch %d, loss=%.6f' % (e, epoch_loss))
            
        
    def predict(self, x, batch_size=2000):
        self.model.eval()
        preds = []
        
        for batch_x in self.next_pred_batch(x, batch_size):
            batch_x_tensor = torch.FloatTensor(batch_x).cuda(self.gpu_id)
            batch_pred_tensor = self.model.forward(batch_x_tensor)
            batch_pred = batch_pred_tensor.data.cpu().detach().numpy()
            
            try:
                m = len(batch_pred)
                for j in range(m):
                    preds.append(batch_pred[j])
            except Exception as e:
                print(e)
                print(batch_pred)
                print(batch_pred.shape)

        return np.array(preds)
    
    